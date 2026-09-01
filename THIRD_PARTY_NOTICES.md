# Third-Party Notices

This project includes or derives from the following third-party software:

## beszel

The front-end of this project is a patched build of
[beszel](https://github.com/henrygd/beszel) (hub UI), and its deployment model
reuses beszel's hub/agent architecture. beszel is licensed under the MIT
License:

> MIT License
>
> Copyright (c) 2024 henrygd
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.

## Inter typeface

The bundled front-end assets include the Inter variable font
(`plugin/dashboard/dist/static/InterVariable.woff2`), licensed under the
SIL Open Font License 1.1 — https://fonts.google.com/specimen/Inter/license

## DB-IP GeoIP database

When deployed, the security collector uses the free "DB-IP City Lite" mmdb
(downloaded at runtime from https://db-ip.com), which is licensed under
CC BY 4.0. The database itself is NOT distributed with this repository.
