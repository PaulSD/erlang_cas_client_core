# CAS Client Library for Erlang

This Erlang OTP application provides a webserver/framework-independent library for performing client side [CAS](http://www.jasig.org/cas) authentication operations.  All features of the published [CAS protocols](http://www.jasig.org/cas/protocol) are supported, as well as SAML 1.1 and [Single-Sign-Out](https://wiki.jasig.org/display/CASUM/Single+Sign+Out).

In general, this library is meant to be used by another webserver/framework-specific library, and is not meant to be used directly.

An example webserver/framework specific library that uses this library can be found at [https://github.com/PaulSD/erlang_cas_client_cowboy](https://github.com/PaulSD/erlang_cas_client_cowboy)

Canonical source can be found at [https://github.com/PaulSD/erlang_cas_client_core](https://github.com/PaulSD/erlang_cas_client_core)

## Configuration

Configuration options should be set in the application environment, typically defined in your app.config file:

```erlang
[
  {cas_client_core, [
    {option_name, option_value},
    ...
  ]}
].
```

Core configuration options are documented in [cas_client_core_config](blob/master/src/cas_client_core_config.erl)

## License

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see [http://www.gnu.org/licenses/](http://www.gnu.org/licenses/).
