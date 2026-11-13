#!/usr/bin/env python3
"""
get npm packages for validation set 
Run:  uv run download-benign-validation-set.py
Needs: requests, tqdm, packaging
"""

import os
import requests
import tarfile
import json
import time
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import threading

# ============================================================================
# CONFIGURATION
# ============================================================================

NPM_SEARCH_URL = "https://api.npms.io/v2/search"
NPM_REGISTRY_URL = "https://registry.npmjs.org/"
NPM_DOWNLOAD_URL = "https://api.npmjs.org/downloads/point/last-month/"

TARGET_PACKAGE_COUNT = 300
VERSIONS_PER_PACKAGE = 3  # Latest, middle, oldest  
MIN_DOWNLOADS = 5000  # Minimum downloads in the last month to consider a package
BASE_DIR = "../benign_packages"  # Output directory for downloaded packages


# PERFORMANCE SETTINGS
MAX_WORKERS = 20  # Concurrent download threads (adjust based on your network)\
CHUNK_SIZE = 1024 * 1024  # 1MB chunks for faster download
REQUEST_TIMEOUT = 30  # seconds
BATCH_SIZE = 100  # Process packages in batches

# ============================================================================
# OPTIMIZED SESSION WITH RETRY LOGIC
# ============================================================================

def create_session():
    """Create a requests session with connection pooling and retry logic"""
    session = requests.Session()
    
    # Retry strategy
    retry_strategy = Retry(
        total=3,
        backoff_factor=0.3,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=MAX_WORKERS,
        pool_maxsize=MAX_WORKERS * 2
    )
    
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    return session

# Thread-local session storage
thread_local = threading.local()

def get_session():
    """Get thread-local session"""
    if not hasattr(thread_local, "session"):
        thread_local.session = create_session()
    return thread_local.session

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def ensure_dir(path):
    """Create directory if it doesn't exist"""
    os.makedirs(path, exist_ok=True)

# ============================================================================
# PACKAGE DISCOVERY (OPTIMIZED)
# ============================================================================

def get_packages_batch(size=250, offset=0):
    """Get batch of packages from npm search API"""
    try:
        session = get_session()
        params = {
            "q": "keywords:utility",
            "size": size,
            "from": offset
        }
        r = session.get(NPM_SEARCH_URL, params=params, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.json().get("results", [])
    except Exception as e:
        print(f"Error fetching batch at offset {offset}: {e}")
        return []

def discover_all_packages():
    """
    Discover all packages first (fast, parallel)
    Returns list of package names that meet download criteria
    """
    print("🔍 Discovering packages...")
    
    all_packages = []
    offset = 0
    
    # Quick discovery phase - get package names only
    while len(all_packages) < TARGET_PACKAGE_COUNT * 2:  # Get extra to filter
        results = get_packages_batch(size=250, offset=offset)
        if not results:
            break
        
        for item in results:
            pkg_name = item["package"]["name"]
            all_packages.append(pkg_name)
        
        offset += 250
        print(f"  Discovered {len(all_packages)} packages...")
    
    print(f"✓ Discovered {len(all_packages)} candidate packages")
    return all_packages

# ============================================================================
# PACKAGE FILTERING
# ============================================================================

def check_package_downloads(pkg_name):
    """Check if package meets download threshold"""
    try:
        session = get_session()
        r = session.get(
            NPM_DOWNLOAD_URL + pkg_name, 
            timeout=REQUEST_TIMEOUT
        )
        downloads = r.json().get("downloads", 0)
        return downloads >= MIN_DOWNLOADS
    except:
        return False

def filter_packages_parallel(package_names):
    """Filter packages by download count (parallel)"""
    print(f"\n📊 Filtering packages by downloads (min: {MIN_DOWNLOADS:,})...")
    
    filtered = []
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(check_package_downloads, pkg): pkg 
            for pkg in package_names
        }
        
        with tqdm(total=len(package_names), desc="Filtering") as pbar:
            for future in as_completed(futures):
                pkg = futures[future]
                try:
                    if future.result():
                        filtered.append(pkg)
                        if len(filtered) >= TARGET_PACKAGE_COUNT:
                            # Cancel remaining tasks
                            for f in futures:
                                f.cancel()
                            break
                except:
                    pass
                pbar.update(1)
    
    print(f"✓ Filtered to {len(filtered)} packages meeting criteria")
    return filtered[:TARGET_PACKAGE_COUNT]

# ============================================================================
# VERSION SELECTION
# ============================================================================

def get_package_versions(pkg_name):
    """Get versions and tarball URLs for a package"""
    try:
        session = get_session()
        r = session.get(
            NPM_REGISTRY_URL + pkg_name,
            timeout=REQUEST_TIMEOUT
        )
        r.raise_for_status()
        data = r.json()
        
        versions = list(data.get("versions", {}).keys())
        if not versions:
            return None
        
        versions = sorted(versions)
        
        # Select versions
        if len(versions) < 3:
            selected = versions
        else:
            selected = [
                versions[-1],           # Latest
                versions[len(versions)//2],  # Middle
                versions[0]             # Oldest
            ]
        
        # Get tarball URLs
        version_data = []
        for v in selected:
            tarball_url = data["versions"][v]["dist"]["tarball"]
            version_data.append({
                "version": v,
                "tarball": tarball_url
            })
        
        return {
            "name": pkg_name,
            "versions": version_data
        }
    
    except Exception as e:
        return None

# ============================================================================
# DOWNLOAD AND EXTRACT (OPTIMIZED)
# ============================================================================

def download_and_extract_package(pkg_data):
    """
    Download and extract a single package version
    Returns tuple: (success, package_name, version)
    """
    pkg_name = pkg_data["name"]
    version = pkg_data["version"]
    tarball_url = pkg_data["tarball"]
    
    pkg_dir = os.path.join(BASE_DIR, pkg_name, version)
    
    # Skip if already downloaded
    if os.path.exists(pkg_dir) and os.listdir(pkg_dir):
        return (True, pkg_name, version, "cached")
    
    ensure_dir(pkg_dir)
    tar_path = os.path.join(pkg_dir, "package.tgz")
    
    try:
        session = get_session()
        
        # Download with streaming
        r = session.get(tarball_url, stream=True, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        
        # Write in large chunks
        with open(tar_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=CHUNK_SIZE):
                if chunk:
                    f.write(chunk)
        
        # Extract
        with tarfile.open(tar_path, "r:gz") as tar:
            tar.extractall(path=pkg_dir)
        
        # Clean up tarball
        os.remove(tar_path)
        
        return (True, pkg_name, version, "downloaded")
    
    except Exception as e:
        # Clean up failed download
        if os.path.exists(tar_path):
            os.remove(tar_path)
        if os.path.exists(pkg_dir) and not os.listdir(pkg_dir):
            os.rmdir(pkg_dir)
        
        return (False, pkg_name, version, str(e))

# ============================================================================
# MAIN PIPELINE
# ============================================================================

def build_dataset():
    """Main pipeline: discover -> filter -> download"""
    
    print("="*70)
    print("NPM PACKAGE DOWNLOADER (OPTIMIZED)")
    print("="*70)
    print(f"Target: {TARGET_PACKAGE_COUNT} packages")
    print(f"Versions per package: {VERSIONS_PER_PACKAGE}")
    print(f"Min downloads: {MIN_DOWNLOADS:,}")
    print(f"Concurrent workers: {MAX_WORKERS}")
    print("="*70)
    
    ensure_dir(BASE_DIR)
    
    start_time = time.time()
    
    # PHASE 1: Discover packages (fast)
    candidate_packages = discover_all_packages()
    
    if not candidate_packages:
        print("❌ No packages discovered")
        return
    
    # PHASE 2: Filter by downloads (parallel)
    selected_packages = filter_packages_parallel(candidate_packages)
    
    if not selected_packages:
        print("❌ No packages meet download criteria")
        return
    
    # PHASE 3: Get version info (parallel)
    print(f"\n📦 Fetching version info for {len(selected_packages)} packages...")
    
    package_metadata = []
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(get_package_versions, pkg): pkg 
            for pkg in selected_packages
        }
        
        with tqdm(total=len(selected_packages), desc="Versions") as pbar:
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        package_metadata.append(result)
                except:
                    pass
                pbar.update(1)
    
    # PHASE 4: Download all versions (parallel)
    print(f"\n⬇️  Downloading {len(package_metadata)} packages...")
    
    # Flatten: create list of all (package, version) combinations
    download_tasks = []
    for pkg_meta in package_metadata:
        for version_data in pkg_meta["versions"]:
            download_tasks.append({
                "name": pkg_meta["name"],
                "version": version_data["version"],
                "tarball": version_data["tarball"]
            })
    
    print(f"   Total downloads: {len(download_tasks)} package versions")
    
    success_count = 0
    cached_count = 0
    fail_count = 0
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(download_and_extract_package, task): task
            for task in download_tasks
        }
        
        with tqdm(total=len(download_tasks), desc="Downloading") as pbar:
            for future in as_completed(futures):
                try:
                    success, pkg, ver, status = future.result()
                    if success:
                        if status == "cached":
                            cached_count += 1
                        else:
                            success_count += 1
                    else:
                        fail_count += 1
                except:
                    fail_count += 1
                
                pbar.update(1)
                pbar.set_postfix({
                    'downloaded': success_count,
                    'cached': cached_count,
                    'failed': fail_count
                })
    
    # Final stats
    elapsed = time.time() - start_time
    
    print("\n" + "="*70)
    print("✓ DOWNLOAD COMPLETE")
    print("="*70)
    print(f"Packages: {len(package_metadata)}")
    print(f"Total versions: {len(download_tasks)}")
    print(f"Downloaded: {success_count}")
    print(f"Cached: {cached_count}")
    print(f"Failed: {fail_count}")
    print(f"Time: {elapsed:.1f} seconds ({elapsed/60:.1f} minutes)")
    print(f"Speed: {len(download_tasks)/elapsed:.1f} packages/sec")
    print("="*70)
    
    # Save metadata
    metadata_path = os.path.join(BASE_DIR, "dataset_metadata.json")
    with open(metadata_path, "w") as f:
        json.dump({
            "total_packages": len(package_metadata),
            "total_versions": len(download_tasks),
            "downloaded": success_count,
            "cached": cached_count,
            "failed": fail_count,
            "elapsed_seconds": elapsed,
            "packages": [p["name"] for p in package_metadata]
        }, f, indent=2)
    
    print(f"Metadata saved to: {metadata_path}")


if __name__ == "__main__":
    build_dataset()