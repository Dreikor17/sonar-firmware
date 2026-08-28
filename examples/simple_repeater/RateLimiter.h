#pragma once

#include <stdint.h>

class RateLimiter {
  uint32_t _start_timestamp;
  uint32_t _secs;
  uint16_t _maximum, _count;

public:
  RateLimiter(uint16_t maximum, uint32_t secs): _maximum(maximum), _secs(secs), _start_timestamp(0), _count(0) { }

  // Change the ceiling WITHOUT resetting the window. Reconstructing the object
  // instead zeroes _count and _start_timestamp, so editing the limit at runtime
  // instantly refills the budget -- and a change applied twice (60 -> 61 -> 60)
  // refills it twice.
  void setMaximum(uint16_t maximum) { _maximum = maximum; }
  uint16_t getMaximum() const { return _maximum; }

  bool allow(uint32_t now) {
    if (now < _start_timestamp + _secs) {
      _count++;
      if (_count > _maximum) return false;   // deny
    } else {   // time window now expired
      _start_timestamp = now;
      _count = 1;
    }
    return true;
  }
};