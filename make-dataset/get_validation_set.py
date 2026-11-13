import random
import shutil
import tarfile
from pathlib import Path
"""
Clone the npmjs-samples repository and extract a random selection of packages to create a validation set.
- The source directory is expected to be "../maloss-samples/npmjs-samples"
- The output directory for the validation set is "../validation-set"
 - The number of packages to select is set by NUM_VALIDATION_PACKAGES (default 95)
- Packages that are part of the training set (listed in TRAINING_PACKAGES) will be excluded from the validation set.
- The random selection is reproducible using RANDOM_SEED.
Usage: uv run get_validation_set.py
"""
# Configuration
SOURCE_DIR = Path("../maloss-samples/npmjs-samples")
TEST_DATA_DIR = Path("../validation-set")
NUM_VALIDATION_PACKAGES = 95
RANDOM_SEED = 42

# Training packages to exclude from validation   set
TRAINING_PACKAGES = {"../dataset-list/test-packages-name.txt"} 


def extract_tgz(tgz_path, dest_dir):
    """Extract a .tgz file to the destination directory"""
    try:
        with tarfile.open(tgz_path, 'r:gz') as tar:
            tar.extractall(dest_dir)
        return True
    except Exception as e:
        print(f"   ❌ Error extracting {tgz_path.name}: {e}")
        return False

def get_package_name_from_tgz(tgz_file):
    """Extract package name from .tgz filename"""
    # Remove .tgz extension and any version numbers
    # e.g., "loadyml-1.0.2.tgz" -> "loadyml"
    name = tgz_file.stem  # removes .tgz
    # Try to remove version pattern (e.g., -1.0.2)
    parts = name.split('-')
    # Usually package name is before version numbers
    # This is a simple heuristic, might need adjustment
    for i, part in enumerate(parts):
        if part[0].isdigit():
            return '-'.join(parts[:i])
    return name

def main():
    # Verify source directory exists
    if not SOURCE_DIR.exists():
        print(f"❌ Error: {SOURCE_DIR} does not exist!")
        return
    
    # Get all .tgz files from npmjs-samples
    all_tgz_files = list(SOURCE_DIR.glob("*.tgz"))
    print(f"📦 Total .tgz files in {SOURCE_DIR}: {len(all_tgz_files)}")
    
    if len(all_tgz_files) == 0:
        print(f"❌ No .tgz files found in {SOURCE_DIR}")
        return
    
    # Map package names to .tgz files
    package_map = {}
    for tgz in all_tgz_files:
        pkg_name = get_package_name_from_tgz(tgz)
        package_map[pkg_name] = tgz
    
    print(f"\n📋 Detected packages:")
    for pkg_name in sorted(package_map.keys())[:10]:  # Show first 10
        print(f"   - {pkg_name}")
    if len(package_map) > 10:
        print(f"   ... and {len(package_map) - 10} more")
    
    # Filter out training packages
    available_packages = {name: tgz for name, tgz in package_map.items() 
                         if name not in TRAINING_PACKAGES}
    
    training_in_source = len(package_map) - len(available_packages)
    
    print(f"\n🔍 Package Analysis:")
    print(f"   Total packages: {len(package_map)}")
    print(f"   Training packages (excluded): {training_in_source}")
    print(f"   Available for test set: {len(available_packages)}")
    
    # Adjust NUM_VALIDATION_PACKAGES if needed
    num_test = NUM_VALIDATION_PACKAGES
    if len(available_packages) < num_test:
        print(f"⚠️  Warning: Only {len(available_packages)} packages available")
        print(f"   Adjusting test set size from {num_test} to {len(available_packages)}")
        num_test = len(available_packages)
    
    if num_test == 0:
        print(f"\n❌ ERROR: No packages available for test set!")
        print(f"   All packages in {SOURCE_DIR} are in your training set.")
        return
    
    # Randomly select test packages
    random.seed(RANDOM_SEED)
    available_names = list(available_packages.keys())
    selected_names = random.sample(available_names, num_test)
    
    # Create test-data directory
    if TEST_DATA_DIR.exists():
        print(f"\n⚠️  {TEST_DATA_DIR} already exists. Remove it? (y/n): ", end='')
        response = input().strip().lower()
        if response == 'y':
            shutil.rmtree(TEST_DATA_DIR)
        else:
            print("❌ Aborted. Please remove or rename existing test-data directory.")
            return
    
    TEST_DATA_DIR.mkdir(exist_ok=True)
    
    # Extract selected packages to test-data
    print(f"\n🔄 Extracting {num_test} packages to {TEST_DATA_DIR}...")
    print("="*70)
    
    successful_extractions = []
    for i, pkg_name in enumerate(sorted(selected_names), 1):
        tgz_file = available_packages[pkg_name]
        print(f"  {i:2d}. {pkg_name:30s} <- {tgz_file.name}")
        
        # Create package directory
        pkg_dir = TEST_DATA_DIR / pkg_name
        pkg_dir.mkdir(exist_ok=True)
        
        # Extract .tgz file
        if extract_tgz(tgz_file, pkg_dir):
            successful_extractions.append(pkg_name)
        
    print("="*70)
    
    # Save test set list for documentation
    test_set_file = Path("test_set_packages.txt")
    with open(test_set_file, "w") as f:
        f.write(f"# Test Set Selection Documentation\n")
        f.write(f"# Random seed: {RANDOM_SEED}\n")
        f.write(f"# Total test packages: {len(successful_extractions)}\n")
        f.write(f"# Source: {SOURCE_DIR.absolute()}\n")
        f.write(f"# Extracted to: {TEST_DATA_DIR.absolute()}\n\n")
        for pkg_name in sorted(successful_extractions):
            tgz_file = available_packages[pkg_name]
            f.write(f"{pkg_name}\t{tgz_file.name}\n")
    
    print(f"\n✅ Successfully created test set!")
    print(f"📁 Location: {TEST_DATA_DIR.absolute()}")
    print(f"📄 Package list saved to: {test_set_file}")
    print(f"✅ Successfully extracted: {len(successful_extractions)}/{num_test} packages")
    
    # Summary statistics
    print(f"\n📊 Summary:")
    print(f"   Training packages (excluded): {training_in_source}")
    print(f"   Test packages (extracted): {len(successful_extractions)}")
    print(f"   Total packages in source: {len(package_map)}")
    
    if training_in_source + len(successful_extractions) > 0:
        total = training_in_source + len(successful_extractions)
        ratio_train = training_in_source / total * 100
        ratio_test = len(successful_extractions) / total * 100
        print(f"   Train/Test ratio: {ratio_train:.1f}% / {ratio_test:.1f}%")
    
    # Count versions/files in test set
    print(f"\n📂 Test Data Structure:")
    for pkg_dir in sorted(TEST_DATA_DIR.iterdir())[:5]:  # Show first 5
        if pkg_dir.is_dir():
            subdirs = [d for d in pkg_dir.iterdir() if d.is_dir()]
            files = [f for f in pkg_dir.iterdir() if f.is_file()]
            print(f"   {pkg_dir.name}: {len(subdirs)} dirs, {len(files)} files")
    
    print(f"\n⚠️  CRITICAL NEXT STEPS:")
    print(f"   1. DO NOT analyze code in test-data/ before finalizing queries!")
    print(f"   2. Verify extraction worked correctly (check a few packages)")
    print(f"   3. Finalize and lock your CodeQL queries")
    print(f"   4. Document query finalization date")
    print(f"   5. Run evaluation on test-data/")
    
    print(f"\n💡 Note: Most npm packages extract to a 'package/' subdirectory")
    print(f"   You may need to adjust your CodeQL scanning paths accordingly")

if __name__ == "__main__":
    main()