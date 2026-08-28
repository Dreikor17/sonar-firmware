#!/usr/bin/env bash
# Compile and run the Observer-Probe host test suites inside a gcc container.
# The three headers under test are pure (stdint/stddef/string.h only), so the
# only include path needed is -I src, matching [env:native] in platformio.ini.
set -u

echo "=== toolchain ==="
g++ --version | head -1

echo
echo "=== installing googletest ==="
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq libgtest-dev >/dev/null 2>&1

GTEST_LIB=""
for c in -lgtest -lgtest_main; do :; done
if ls /usr/lib/*/libgtest.a >/dev/null 2>&1 || ls /usr/lib/libgtest.a >/dev/null 2>&1; then
  echo "prebuilt libgtest found"
  GTEST_LIB="-lgtest -lgtest_main -pthread"
else
  echo "no prebuilt lib; building googletest from /usr/src/googletest"
  apt-get install -y -qq cmake >/dev/null 2>&1
  cmake -S /usr/src/googletest -B /tmp/gtb >/dev/null 2>&1
  cmake --build /tmp/gtb -j"$(nproc)" >/dev/null 2>&1
  cp /tmp/gtb/lib/*.a /usr/lib/ 2>/dev/null || cp /tmp/gtb/googletest/*.a /usr/lib/ 2>/dev/null
  GTEST_LIB="-lgtest -lgtest_main -pthread"
fi

fail=0
declare -a SUMMARY=()

for t in protocol policy codec secret; do
  src="test/test_probe_${t}/test_probe_${t}.cpp"
  echo
  echo "================================================================"
  echo "=== SUITE: ${t}   (${src})"
  echo "================================================================"
  if [ ! -f "$src" ]; then
    echo "MISSING: $src"; fail=1; SUMMARY+=("${t}: MISSING"); continue
  fi
  # -Wall so latent problems in never-compiled test code surface here.
  if ! g++ -std=c++17 -Wall -Wextra -Wno-unused-parameter -I src "$src" \
        $GTEST_LIB -o "/tmp/t_${t}" 2>/tmp/cc_${t}.log; then
    echo "--- COMPILE FAILED ---"
    cat "/tmp/cc_${t}.log"
    fail=1; SUMMARY+=("${t}: COMPILE FAILED"); continue
  fi
  if [ -s "/tmp/cc_${t}.log" ]; then
    echo "--- compiler warnings ---"
    cat "/tmp/cc_${t}.log"
  fi
  if "/tmp/t_${t}"; then
    SUMMARY+=("${t}: PASS")
  else
    fail=1; SUMMARY+=("${t}: TEST FAILURES")
  fi
done

echo
echo "================================================================"
echo "=== SUMMARY"
for s in "${SUMMARY[@]}"; do echo "    $s"; done
echo "================================================================"
exit $fail
