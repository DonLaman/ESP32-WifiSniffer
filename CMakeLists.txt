cmake_minimum_required(VERSION 3.16)

# Forza il target ESP32-S3 PRIMA di includere project.cmake
set(IDF_TARGET "esp32s3")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(sniffer_wifi)