#!/usr/bin/env bash

set -euo pipefail

script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_directory
# shellcheck source-path=SCRIPTDIR
# shellcheck source=android-toolchain.sh
source "$script_directory/android-toolchain.sh"
repository_root="$(cd "$script_directory/.." && pwd)"
readonly repository_root
integration_package="$repository_root/IntegrationTests/Android"
readonly integration_package

fail() {
  echo "error: $*" >&2
  exit 1
}

command -v swift >/dev/null 2>&1 || fail "Swift $ANDROID_SWIFT_VERSION is required but 'swift' is not on PATH."

swift_version_output="$(swift --version 2>&1)"
if [[ "$swift_version_output" != *"Swift version $ANDROID_SWIFT_VERSION"* ]]; then
  fail "the official Android SDK requires a matching Swift $ANDROID_SWIFT_VERSION host toolchain; found: ${swift_version_output//$'\n'/ }"
fi

swift_sdk_location_arguments=()
if [[ -n "${ANDROID_SWIFT_SDKS_PATH:-}" ]]; then
  swift_sdk_location_arguments=(--swift-sdks-path "$ANDROID_SWIFT_SDKS_PATH")
fi
readonly swift_sdk_location_arguments

installed_sdks="$(swift sdk list "${swift_sdk_location_arguments[@]}" 2>&1)" || fail "unable to list installed Swift SDKs: $installed_sdks"
if ! grep -Fqx "$ANDROID_SWIFT_SDK_ID" <<<"$installed_sdks"; then
  cat >&2 <<EOF
error: Swift SDK '$ANDROID_SWIFT_SDK_ID' is not installed.
Install it with the official checksum-verified command, then configure it with Android NDK $ANDROID_NDK_RELEASE or later:
  swift sdk install '$ANDROID_SWIFT_SDK_URL' --checksum '$ANDROID_SWIFT_SDK_CHECKSUM'
EOF
  exit 1
fi

readonly android_ndk_directory="${ANDROID_NDK_HOME:-}"
[[ -n "$android_ndk_directory" ]] || fail "ANDROID_NDK_HOME is not set. Point it at Android NDK $ANDROID_NDK_RELEASE or later."
[[ -d "$android_ndk_directory" ]] || fail "ANDROID_NDK_HOME is not a directory: $android_ndk_directory"

readonly ndk_properties="$android_ndk_directory/source.properties"
[[ -f "$ndk_properties" ]] || fail "cannot verify the Android NDK revision because '$ndk_properties' is missing."

ndk_revision="$(sed -n 's/^Pkg\.Revision[[:space:]]*=[[:space:]]*//p' "$ndk_properties" | head -n 1)"
[[ -n "$ndk_revision" ]] || fail "cannot read Pkg.Revision from '$ndk_properties'."

ndk_major="${ndk_revision%%.*}"
ndk_remainder="${ndk_revision#*.}"
ndk_minor="${ndk_remainder%%.*}"
if [[ ! "$ndk_major" =~ ^[0-9]+$ || ! "$ndk_minor" =~ ^[0-9]+$ ]]; then
  fail "cannot compare Android NDK revision '$ndk_revision'; expected a numeric Pkg.Revision."
fi
if ((
  ndk_major < ANDROID_NDK_MINIMUM_MAJOR
  || (ndk_major == ANDROID_NDK_MINIMUM_MAJOR && ndk_minor < ANDROID_NDK_MINIMUM_MINOR)
)); then
  fail "Android NDK $ANDROID_NDK_RELEASE or later is required; found Pkg.Revision $ndk_revision."
fi

echo "Swift host toolchain: $ANDROID_SWIFT_VERSION"
echo "Swift Android SDK: $ANDROID_SWIFT_SDK_ID"
echo "Android NDK: $ndk_revision"

readonly target_triples=(
  "x86_64-unknown-linux-android${ANDROID_API_LEVEL}"
  "aarch64-unknown-linux-android${ANDROID_API_LEVEL}"
)
readonly configurations=(debug release)

for target_triple in "${target_triples[@]}"; do
  for configuration in "${configurations[@]}"; do
    echo "Building Echo Android smoke executable for $target_triple ($configuration)"
    swift build \
      "${swift_sdk_location_arguments[@]}" \
      --package-path "$integration_package" \
      --scratch-path "$repository_root/.build/android" \
      --configuration "$configuration" \
      --swift-sdk "$target_triple" \
      --static-swift-stdlib \
      --product EchoAndroidSmoke
  done
done
