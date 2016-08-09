# Capone

[![Travis](https://travis-ci.org/capone-project/capone-core.svg)](https://travis-ci.org/capone-project/capone-core)
[![AppVeyor](https://ci.appveyor.com/api/projects/status/feco301rukj2nhb7?svg=true)](https://ci.appveyor.com/project/pks-t/capone-core/branch/master)
[![Coverity](https://scan.coverity.com/projects/9691/badge.svg)](https://scan.coverity.com/projects/capone-project-capone-core)

Capone is a generic service framework which can be used to
connect different resources with each other. The overarching aim
is to have all network traffic completely authenticated and
secure, such that noone is able to perform unintended actions,
except people having the right to do so.

To achieve this goal, Capone uses capabilities. A capability is
bound to a certain user and grants him the right to perform a
single, clearly defined action. After a capability has been
issued, the person for whom the capability has been created may
present it to the service to then execute the desired action.

This project provides core functionality, that is the server
which handles access control and mediates access to service
plugins, a simple service discovery daemon as well as a command
line client to access functionality.

The project is licensed under the GPLv3 license. See the LICENSE
file or https://www.gnu.org/licenses/gpl-3.0.en.html for more
information.

## Requirements

- GCC or Clang
- protobuf v2.5.0 or greater
- protobuf-c v1.0.2 or greater
- libsodium v1.0.8 or greater
- cmocka (optional, for tests only)

## API documentation

[Doxygen](https://capone-project.github.io/capone-core/doxygen)
