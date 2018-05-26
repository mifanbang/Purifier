# Purifier
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/ea2e5b05ae0a4457abb05fe7f36fdfe2)](https://www.codacy.com/app/mifanbang/Purifier?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=mifanbang/Purifier&amp;utm_campaign=Badge_Grade)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/15750/badge.svg)](https://scan.coverity.com/projects/mifanbang-purifier)
<br>Removing advertisement banners in Skype prior to version 8.

## Disclaimers

In addition to the lack of warranty as this software is distributed, the use of this software may lead to violation of the Skype Term of Use and/or any other agreement that you have agreed with Skype Inc. or Microsoft Inc. Please be aware of that you are at your own risk.

## Introduction

Advertisement banners embedded in Skype are ugly and sometimes steal input focus while we type. Purifier is a launcher bringing a clean Skype back to you. It requires no installation nor modification of system files. Just run it and everything will be cool.

## Instructions for Use

1. Exit running Skype and make sure it disappeared in the list of Task Manager.
2. Run Purifier.
3. Done.

## Building the Code

The solution file and project files in this repository are maintained with Visual Studio 2017 (get one for free at https://www.visualstudio.com/vs/community/). Support of various features in C++14 and the function attribute __declspec(naked) are required if you are building with other compilers. Please also note that Purifier uses DLL injection as its core mechanism and Skype is still built as 32-bit application, so there's no reason to build a 64-bit version of Purifier.

## Notes on Anti-Virus Software

Some ill-developed anti-virus software may report Purifier as malware. Please do not panic. You can either add Purifier into the exception list of your AV (if you trust this software) or submit a report in the [Issues page](https://github.com/mifanbang/Purifier/issues).

## Copyright

Copyright (C) 2011-2018 Mifan Bang <https://debug.tw>.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.
