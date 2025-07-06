PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Configuration of extension
EXT_NAME=age
EXT_CONFIG=${PROJ_DIR}extension_config.cmake

# Optimization flags for faster builds
ifneq ($(CI),)
	# In CI: Use ninja generator and parallel builds
	GENERATOR := -G Ninja
	MAKEFLAGS += -j$(shell nproc)
else
	# Local development: detect available tools
	ifeq ($(shell which ninja 2>/dev/null),)
		# Ninja not available, use make with parallel jobs
		MAKEFLAGS += -j$(shell nproc 2>/dev/null || echo 4)
	else
		# Ninja available, use it
		GENERATOR := -G Ninja
	endif
endif

# Add ccache if available and not already set
ifeq ($(origin CC),default)
	ifneq ($(shell which ccache 2>/dev/null),)
		CC := ccache gcc
	endif
endif

ifeq ($(origin CXX),default)
	ifneq ($(shell which ccache 2>/dev/null),)
		CXX := ccache g++
	endif
endif

# Include the Makefile from extension-ci-tools
include extension-ci-tools/makefiles/duckdb_extension.Makefile