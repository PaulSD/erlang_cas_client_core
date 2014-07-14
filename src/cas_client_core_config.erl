%%%-------------------------------------------------------------------------------------------------
%%%
%%% Copyright 2013 Paul Donohue <erlang_cas_client_core@PaulSD.com>
%%%
%%% This file is part of erlang_cas_client_core.
%%%
%%% erlang_cas_client_core is free software: you can redistribute it and/or modify it under the
%%% terms of the GNU Lesser General Public License as published by the Free Software Foundation,
%%% either version 3 of the License, or (at your option) any later version.
%%%
%%% erlang_cas_client_core is distributed in the hope that it will be useful, but WITHOUT ANY
%%% WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
%%% PURPOSE.  See the GNU Lesser General Public License for more details.
%%%
%%% You should have received a copy of the GNU Lesser General Public License along with
%%% erlang_cas_client_core.  If not, see {http://www.gnu.org/licenses/}.
%%%
%%%-------------------------------------------------------------------------------------------------

%% @doc Core CAS Client Configuration, read from the 'cas_client_core' application environment.
%%
%% Core options:
%% cas_base_url			(Required option; no default)
%%   The CAS Base URL (as a binary string), with no trailing "/".  For example,
%%   <<"https://server/cas">>.
%% cas_protocol			(Required option; no default)
%%   The CAS Protocol to use.  Valid options are 'cas10', 'cas20', and 'saml11'.
%% gateway			(Default is 'false')
%%   Whether CAS "Gateway" authentication should be requested.  Cannot be used with 'renew'.
%%   (See http://www.jasig.org/cas/client-integration/gateway)
%% renew			(Default is 'false')
%%   Whether CAS "Renew" authentication should be requested.  Cannot be used with 'gateway'.
%%   (See http://www.jasig.org/cas/client-integration/renew)
%% pgt_callback_url		(Default is 'undefined')
%%   The callback URL (as a binary string) which CAS should use to deliver PGTs, or 'undefined' if
%%   Proxy Tickets will not be issued by this web application.
%% allowed_proxy_chains		(Default is 'undefined')
%%   The list of allowed proxy chains.  Each proxy chain should be a list of URLs as binary strings.
%%   For example: {allowed_proxy_chains, [[<<"https://example.com/pgt">>]]}
%%   In place of a list of allowed proxy chains, the token 'any' may be used to accept any proxy
%%   chain, or 'undefined' to reject all proxy tickets.
%% max_validate_attempts	(Default is 2)
%%   The maximum number of times a "soft" validation failure should be retried before giving up.
%% httpc_options		(Default is [])
%%   HTTPC Profile Options. (See http://erlang.org/doc/man/httpc.html#set_options-1)
%%   Most notably:
%%     {proxy, {{Host::string(), Port::integer()}, []}} -> Use an outbound proxy for HTTP
%%     {https_proxy, {{Host::string(), Port::integer()}, []}} -> Use an outbound proxy for HTTPS
%%     (Prior to B16, the 'proxy' option applied to both HTTP and HTTPS)
%%   The following defaults are used by cas_client_core but may be overridden by this option:
%%     {max_sessions, 100}, {keep_alive_timeout, 30000}
%% httpc_httpoptions		(Default is [])
%%   HTTPC Request HTTPOptions. (See http://erlang.org/doc/man/httpc.html#request-4)
%%   Most notably:
%%     {connect_timeout, integer()} -> Override the default connection establishment timeout
%%     {timeout, integer()} -> Override the default connection idle timeout
%%     {autoredirect, true} -> Follow HTTP 3XX redirects
%%   The following defaults are used by cas_client_core but may be overridden by this option:
%%     {connect_timeout, 10000}, {timeout, 10000}, {autoredirect, false}
%% ssl_options			(Default is [])
%%   SSL options for HTTPS requests. (See http://erlang.org/doc/man/ssl.html)
%%   Most notably:
%%     {verify, verify_peer} -> Verify server certificate
%%     {cacertfile, Path::string()} -> Trusted CA certs for server cert verification
%%     {versions, [tlsv1, 'tlsv1.1', 'tlsv1.2']} -> Limit allowed SSL/TLS protocol versions
%%   The following defaults are used by cas_client_core but may be overridden by this option:
%%     {secure_renegotiate, true}, {depth, 10}
%%
-module(cas_client_core_config).

-export([get/1, get_default/1, validate/2, validate/1]).

%% @doc Read the specified configuration value (or its documented default) from the
%% 'cas_client_core' application environment.  Returns 'undefined' if the value does not exist and
%% does not have a documented default value.
-spec get(Key) -> Value when Key::atom(), Value::any().
get(Key) ->
  case application:get_env(cas_client_core, Key) of
  undefined -> get_default(Key);
  {ok, Value} -> Value
  end.

%% @doc Return the documented default value for the specified configuration key.  Returns
%% 'undefined' if the specified configuration key does not have a documented default value.
-spec get_default(Key) -> Value when Key::atom(), Value::any().
get_default(Key) ->
  case Key of
  gateway -> false;
  renew -> false;
  max_validate_attempts -> 2;
  httpc_options -> [];
  httpc_httpoptions -> [];
  ssl_options -> [];
  _ -> undefined
  end.

%% @doc Validate the data type of the specified option.
-spec validate(Key, Value) -> ok | {error, Message}
  when Key::atom(), Value::any(), Message::string().
validate(Key, Value) ->
  CheckFun =
    case Key of
    cas_base_url -> fun(X) when is_binary(X) -> X end;
    cas_protocol -> fun(X) when X =:= cas10 orelse X =:= cas20 orelse X =:= saml11 -> X end;
    gateway -> fun(X) when is_boolean(X) -> X end;
    renew -> fun(X) when is_boolean(X) -> X end;
    pgt_callback_url -> fun(X) when X =:= undefined orelse is_binary(X) -> X end;
    allowed_proxy_chains -> fun(X) when X=:= undefined orelse X =:= any orelse is_list(X) -> X end;
    max_validate_attempts -> fun(X) when is_integer(X) andalso X >= 1 -> X end;
    httpc_options -> fun(X) when is_list(X) -> X end;
    httpc_httpoptions -> fun(X) when is_list(X) -> X end;
    ssl_options -> fun(X) when is_list(X) -> X end;
    _ -> fun(X) -> X end
    end,
  case catch CheckFun(Value) of
  {'EXIT', _} ->
    {error, io_lib:format("cas_client_core configuration problem: Invalid ~s: ~p", [Key, Value])};
  _ -> ok
  end.

%% @doc Validate presence of required options and data types of all options.
-spec validate(cas_client_core:config_get_fun()) -> ok | {error, Message} when Message::string().
validate(ConfigFun) ->
  %% Validate presence of required options
  BaseURL = cas_client_core:config(cas_base_url, ConfigFun),
  Protocol = cas_client_core:config(cas_protocol, ConfigFun),
  case BaseURL =:= undefined orelse Protocol =:= undefined of
  true ->
    {error, "cas_client_core configuration problem: cas_base_url and cas_protocol must be specified"};
  false ->
    %% Prevent 'gateway' and 'renew' from being enabled at the same time
    case cas_client_core:config(gateway, ConfigFun) =:= true andalso
      cas_client_core:config(renew, ConfigFun) =:= true of
    true ->
      {error, "cas_client_core configuration problem: gateway and renew cannot be enabled at the same time"};
    false ->
      %% Validate data types of configured options
      Options = [cas_base_url, cas_protocol, gateway, renew, pgt_callback_url, allowed_proxy_chains,
        max_validate_attempts, httpc_options, httpc_httpoptions, ssl_options],
      lists:foldl(
        fun
        (O, ok) -> validate(O, cas_client_core:config(O, ConfigFun));
        (_O, A) -> A
        end,
      ok, Options)
    end
  end.
