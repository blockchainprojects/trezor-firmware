#!/usr/bin/env bash

: "${RUN_TEST_EMU:=1}"

CORE_DIR="$(SHELL_SESSION_FILE='' && cd "$( dirname "${BASH_SOURCE[0]}" )/.." >/dev/null 2>&1 && pwd )"
MICROPYTHON="${MICROPYTHON:-$CORE_DIR/build/unix/micropython}"
TREZOR_SRC="${CORE_DIR}/src"

PYOPT="${PYOPT:-0}"
upy_pid=""

# run emulator if RUN_TEST_EMU
if [[ $RUN_TEST_EMU > 0 ]]; then
  source ../trezor_cmd.sh

  # remove flash and sdcard files before run to prevent inconsistent states
  mv "${TREZOR_PROFILE_DIR}/trezor.flash" "${TREZOR_PROFILE_DIR}/trezor.flash.bkp" 2>/dev/null
  mv "${TREZOR_PROFILE_DIR}/trezor.sdcard" "${TREZOR_PROFILE_DIR}/trezor.sdcard.bkp" 2>/dev/null

  cd "${TREZOR_SRC}"
  echo "Starting emulator: $MICROPYTHON $ARGS ${MAIN}"

  TREZOR_TEST=1 \
  TREZOR_DISABLE_ANIMATION=1 \
    $MICROPYTHON $ARGS "${MAIN}" &> "${TREZOR_LOGFILE}" &
  upy_pid=$!
  cd -
  sleep 30
fi

# run tests
error=0
if ! pytest --junitxml=../../tests/junit.xml ../../tests/device_tests "$@"; then
  error=1
fi
kill $upy_pid
exit $error
