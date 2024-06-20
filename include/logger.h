/*Copyright (C) 2017  Nebojsa Stojiljkovic

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>*/
                                            
/**
 * The code copied from https://www.linkedin.com/pulse/more-useful-c-macros-improve-printf-functionality-stojiljkovic/
 * and modified based on my needs
 */


#ifndef LOGGER_H_
#define LOGGER_H_

#include <stdio.h>

#if LOG_INFO
#define INFO(...)    \
    {\
    printf("INFO: ");  \
    printf(__VA_ARGS__); \
    printf("\r\n"); \
    }
#else
#define INFO(...)
#endif

#if LOG_DEBUG
#define DEBUG(...)    \
    {\
    printf("DEBUG: Function: %s Line: #%d ", __PRETTY_FUNCTION__, __LINE__);  \
    printf(__VA_ARGS__); \
    printf("\r\n"); \
    }
#else
#define DEBUG(...)
#endif

#if LOG_WARN
#define WARN(...)   \
    { \
    printf("WARN: Function: %s Line: #%d ", __PRETTY_FUNCTION__, __LINE__);  \
    printf(__VA_ARGS__); \
    printf("\r\n"); \
    }
#else
#define WARN(...)
#endif

#if LOG_ERROR
#define ERROR(...)  \
    { \
    printf("ERROR: Function: %s Line: #%d ", __PRETTY_FUNCTION__, __LINE__); \
    printf(__VA_ARGS__); \
    printf("\r\n"); \
    }
#else
#define ERROR(...)
#endif


#endif /*LOGGER_H_*/
