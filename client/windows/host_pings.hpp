#pragma once
#include "inventory.hpp"
#include <atomic>
#include <functional>

void measure_host_pings(Json& transfer, const std::atomic_bool& cancel,
                        const std::function<void()>& checkpoint);
