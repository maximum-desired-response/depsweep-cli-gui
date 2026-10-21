#!/usr/bin/env bash
# ===================================================================
# DepSweep Standalone Compilation Script (Isolated Environment Sandbox)
# ===================================================================
set -eEu -o pipefail

SRC_FILE="depsweep.py"
OUTPUT_NAME="depsweep"

# Configuration variables allowing flexible persistent storage migrations
BUILD_ROOT="./"
BUILD_ENV="${BUILD_ROOT}/depsweep_isolated_compiler_env"
OUTPUT_DIR="./build_output"

echo "[INFO] Verifying source file..."
if [[ ! -f "${SRC_FILE}" ]]; then
    echo "[ERROR] Source file '${SRC_FILE}' not found in the current directory!" >&2
    exit 1
fi

# Clean up any stale build structures (Leaves BUILD_ENV alone if choosing persistent roots)
rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"

# If using a persistent BUILD_ROOT, we skip downloading toolchains every run if they exist
if [[ ! -d "${BUILD_ENV}" ]]; then
    echo "[INFO] Engineering fresh isolated Python virtual environment..."
    mkdir -p "$(dirname "${BUILD_ENV}")"
    python3 -m venv "${BUILD_ENV}"

    source "${BUILD_ENV}/bin/activate"
    echo "[INFO] Upgrading toolchain dependencies inside workspace..."
    pip install --upgrade pip setuptools wheel
    pip install nuitka ordered-set patchelf PySide6
else
    echo "[INFO] Utilizing existing environment sandbox found at: ${BUILD_ENV}"
    source "${BUILD_ENV}/bin/activate"
fi

echo "[INFO] Compiling '${SRC_FILE}' into an isolated binary..."
python3 -m nuitka \
    --update-check=never \
    --jobs=-1 \
    --onefile \
    --onefile-tempdir-spec="{HOME}/.cache/nuitka-vault" \
    --plugin-enable=pyside6 \
    --include-qt-plugins=sensible,platforms,platformthemes,platforminputcontexts,xcbglintegrations,imageformats,iconengines \
    --nofollow-import-to=PyQt6 \
    --nofollow-import-to=PIL \
    --nofollow-import-to=pillow \
    --deployment \
    --lto=yes \
    --output-dir="${OUTPUT_DIR}" \
    "${SRC_FILE}"

deactivate

echo "[INFO] Commencing file system sanitization pass..."
GENERATED_BIN=$(find "${OUTPUT_DIR}" -maxdepth 1 -type f ! -name "*.py" ! -name "*.sh" ! -name "*.txt" -executable | head -n 1)

if [ -n "${GENERATED_BIN}" ]; then
    mv "${GENERATED_BIN}" "./${OUTPUT_NAME}"
    chmod 755 "./${OUTPUT_NAME}"
    echo "--------------------------------------------------------"
    echo "[SUCCESS] DepSweep successfully compiled via isolated sandbox!"
    echo "          Executable located at: ./${OUTPUT_NAME}"
    echo "--------------------------------------------------------"
else
    echo "[ERROR] Nuitka compilation completed but no binary file was found." >&2
    rm -rf "${OUTPUT_DIR}"
    exit 1
fi

# Clean up temporary intermediary build artifacts
rm -rf "${OUTPUT_DIR}"

# Clean up the virtual environment only if it resides in volatile volatile memory space (/tmp)
if [[ "${BUILD_ROOT}" == "/tmp" ]]; then
    rm -rf "${BUILD_ENV}"
    echo "[INFO] Volatile compiler environment sanitized."
else
    echo "[INFO] Persistent environment cache preserved inside: ${BUILD_ROOT}"
fi
echo "[INFO] Staging complete."
