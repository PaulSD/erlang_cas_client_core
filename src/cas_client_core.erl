%%%-------------------------------------------------------------------------------------------------
%%%
%%% Copyright 2013 Paul Donohue <erlang_cas_client_core@PaulSD.com>
%%%
%%% This program is free software: you can redistribute it and/or modify
%%% it under the terms of the GNU General Public License as published by
%%% the Free Software Foundation, either version 3 of the License, or
%%% (at your option) any later version.
%%%
%%% This program is distributed in the hope that it will be useful,
%%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
%%% GNU General Public License for more details.
%%%
%%% You should have received a copy of the GNU General Public License
%%% along with this program.  If not, see {http://www.gnu.org/licenses/}.
%%%
%%%-------------------------------------------------------------------------------------------------

%% @doc CAS Client Library
-module(cas_client_core).

-export([config/2, login_url/2, logout_url/2, validate/3, pgt_iou/2, proxy_ticket/3,
         parse_single_sign_out_request/1]).
-export([user/1, attribute/2]).

-export([url_encode/1, current_time/0]).

-export([start/0]).
-behaviour(application).
-export([start/2, stop/1]).

-export([httpc_request/4]).

-type config_get_fun() :: undefined | fun((Key::atom()) -> Value::binary()).
-type attributes() :: not_authenticated | list({Key::binary(), Value::binary()}).
-export_type([config_get_fun/0, attributes/0]).

-record(pgt_iou, {iou, pgt, timestamp}).

-include_lib("xmerl/include/xmerl.hrl").



%%%=================================================================================================
%%% CAS API

%% @doc Read the specified configuration value (or its documented default) from the specified
%% config function (or cas_client_core_config::get() if ConfigFun is 'undefined').
-spec config(Key, ConfigFun) -> Value when Key::atom(), Value::any(), ConfigFun::config_get_fun().
config(Key, ConfigFun) ->
  case ConfigFun of
  undefined -> cas_client_core_config:get(Key);
  _ -> ConfigFun(Key)
  end.

%% @doc Return the URL which a client should be redirected to for login via CAS.  CAS will redirect
%% the client back to the specified Service URL.
-spec login_url(ServiceURL, ConfigFun) -> LoginURL
  when ServiceURL::binary(), LoginURL::binary(), ConfigFun::config_get_fun().
login_url(ServiceURL, ConfigFun) ->
  Gateway = case config(gateway, ConfigFun) of true -> <<"&gateway=true">>; false -> <<>> end,
  Renew = case config(renew, ConfigFun) of true -> <<"&renew=true">>; false -> <<>> end,
  <<(config(cas_base_url, ConfigFun))/binary, "/login?service=", (url_encode(ServiceURL))/binary,
    Gateway/binary, Renew/binary>>.

%% @doc Return the URL which a client should be redirected to for CAS logout.  CAS will optionally
%% provide a link to the specified App URL on the logout confirmation page.
-spec logout_url(undefined | AppURL, ConfigFun) -> LogoutURL
  when AppURL::binary(), LogoutURL::binary(), ConfigFun::config_get_fun().
logout_url(AppURL, ConfigFun) ->
  URL = case AppURL of undefined -> <<>>; _ -> <<"?url=", AppURL/binary>> end,
  <<(config(cas_base_url, ConfigFun))/binary, "/logout", URL/binary>>.

%% @doc Validate the specified CAS Ticket associated with the specified Service URL and return the
%% associated CAS attributes.  Returns 'retry' if a "soft" error occurred but the caller may
%% redirect the client back to CAS to try again (the caller should limit the number of times it
%% attempts to retry).  Returns 'error' if a "hard" error occurred and the caller should not try
%% again (an error message should be displayed to the user).
-spec validate(Ticket, ServiceURL, ConfigFun) -> {ok, attributes()} | retry | error
  when Ticket::binary(), ServiceURL::binary(), ConfigFun::config_get_fun().
validate(Ticket, ServiceURL, ConfigFun) ->
  CASProto = config(cas_protocol, ConfigFun),
  ValidatePath =
    case {CASProto, config(allowed_proxy_chains, ConfigFun)} of
    {cas10, _} -> <<"validate">>;
    {cas20, undefined} -> <<"serviceValidate">>;
    {cas20, _} -> <<"proxyValidate">>;
    {saml11, _} -> <<"samlValidate">>
    end,
  Params =
    case CASProto of
    saml11 -> <<"?TARGET=", (url_encode(ServiceURL))/binary>>;
    _ -> <<"?ticket=", (url_encode(Ticket))/binary, "&service=", (url_encode(ServiceURL))/binary>>
    end,
  Renew = case config(renew, ConfigFun) of true -> <<"&renew=true">>; false -> <<>> end,
  PGTURL =
    case config(pgt_callback_url, ConfigFun) of
    undefined -> <<>>;
    U -> <<"&pgtUrl=", (url_encode(U))/binary>>
    end,
  ValidateURL =
    <<(config(cas_base_url, ConfigFun))/binary, "/", ValidatePath/binary, Params/binary,
      Renew/binary, PGTURL/binary>>,
  lager:debug("Calling ~s", [ValidateURL]),
  Return =
    case CASProto of
    saml11 ->
      {{Year, Mon, Day}, {Hour, Min, Sec}} = calendar:universal_time(),
      Date = <<(integer_to_binary(Year))/binary, "-", (integer_to_binary(Mon))/binary, "-",
               (integer_to_binary(Day))/binary, "T", (integer_to_binary(Hour))/binary, ":",
               (integer_to_binary(Min))/binary, ":", (integer_to_binary(Sec))/binary, ".000Z">>,
      ReqBody =
        <<"<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\">",
          "<SOAP-ENV:Header/><SOAP-ENV:Body>",
          "<samlp:Request xmlns:samlp=\"urn:oasis:names:tc:SAML:1.0:protocol\" MajorVersion=\"1\" ",
          "MinorVersion=\"1\" IssueInstant=\"", Date/binary, "\">",
          "<samlp:AssertionArtifact>", Ticket/binary, "</samlp:AssertionArtifact>",
          "</samlp:Request></SOAP-ENV:Body></SOAP-ENV:Envelope>">>,
      httpc_request(post, {ValidateURL, [], "text/xml", ReqBody}, [], ConfigFun);
    _ ->
      httpc_request(get, {ValidateURL, []}, [], ConfigFun)
    end,
  case Return of
  {ok, {{_HTTPVersion, 200, _ReasonPhrase}, _Headers, Body}} ->
    process_cas_response(Ticket, Body, ConfigFun);
  {ok, {{_HTTPVersion, StatusCode, ReasonPhrase}, _Headers, Body}} ->
    lager:warning("Received HTTP ~b (~s) error from ~s with body:~n~s", [StatusCode, ReasonPhrase, ValidateURL, Body]),
    retry;
  {error, {failed_connect, [_, {_, _, timeout}]} = Reason} ->
    lager:warning("Timed out establishing connection to ~s : ~p", [ValidateURL, Reason]),
    retry;
  {error, {failed_connect, _} = Reason} ->
    lager:warning("Error establishing connection to ~s : ~p", [ValidateURL, Reason]),
    retry;
  {error, timeout} ->
    lager:warning("Timed out while retrieving ~s", [ValidateURL]),
    retry;
  {error, Reason} ->
    lager:warning("Error while retrieving ~s : ~p", [ValidateURL, Reason]),
    retry;
  ReplyInfo ->
    lager:error("Received unexpected ReplyInfo from httpc for ~s : ~p", [ValidateURL, ReplyInfo]),
    error
  end.

%% @doc Accept a PGT-IOU and associated PGT from CAS.
-spec pgt_iou(PGTiou::binary(), PGT::binary()) -> ok.
pgt_iou(PGTiou, PGT) ->
  lager:debug("Received PGT ~s associated with PGT-IOU ~s from CAS", [PGT, PGTiou]),
  clean_unclaimed_pgts(),
  ets:insert(?MODULE, #pgt_iou{iou = PGTiou, pgt = PGT, timestamp = current_time()}),
  ok.

%% @doc Return a CAS Proxy Ticket associated with the specified Service URL for the user associated
%% with the specified CAS authentication attributes.  Returns 'not_authenticated' if the attributes
%% indicate no CAS authentication.  Returns 'undefined' if there is no PGT associated with the
%% authenticated user.  Returns 'retry' if a "soft" error occurred but the caller may try again (the
%% caller should limit the number of times it attempts to retry).  Returns 'error' if a "hard" error
%% occurred and the caller should not try again.
-spec proxy_ticket(ServiceURL, attributes(), ConfigFun) ->
  not_authenticated | undefined | {ok, Ticket} | retry | error
  when ServiceURL::binary(), Ticket::binary(), ConfigFun::config_get_fun().
proxy_ticket(ServiceURL, Attrs, ConfigFun) ->
  case Attrs of
  not_authenticated ->
    lager:debug("Returning not_authenticated to Proxy Ticket request for Service ~s", [ServiceURL]),
    not_authenticated;
  _ ->
    case attribute(<<"proxyGrantingTicket">>, Attrs) of
    undefined ->
      lager:debug("Returning undefined to Proxy Ticket request for Service ~s with CAS attributes ~p", [ServiceURL, Attrs]),
      undefined;
    PGT ->
      ProxyURL = <<(config(cas_base_url, ConfigFun))/binary, "/proxy?pgt=", PGT/binary,
        "&targetService=", (url_encode(ServiceURL))/binary>>,
      lager:debug("Calling ~s", [ProxyURL]),
      case httpc_request(get, {ProxyURL, []}, [], ConfigFun) of
      {ok, {{_HTTPVersion, 200, _ReasonPhrase}, _Headers, Body}} ->
        case catch parse_xml(Body) of
        {'EXIT', Reason} ->
          lager:warning("Error parsing response from CAS: ~p~nCAS Response:~n~s", [Reason, Body]),
          retry;  %% Might be an error message instead of a CAS response, worth trying again
        Doc ->
          case Doc of
          #xmlElement{name = 'cas:serviceResponse', content = RespContent} ->
            case RespContent of
            [#xmlElement{name = 'cas:proxySuccess', content = SuccessContent}] ->
              case SuccessContent of
              [#xmlElement{name = 'cas:proxyTicket', content = [#xmlText{value = PT1}]}] ->
                PT = list_to_binary(string:strip(PT1)),
                lager:debug("Generated Proxy Ticket ~s for Service ~s associated with CAS attributes ~p", [PT, ServiceURL, Attrs]),
                {ok, PT};
              El ->
                lager:error("Unexpected XML contents in response from CAS: ~p~nCAS Response:~n~s", [El, Body]),
                error
              end;
            [#xmlElement{name = 'cas:proxyFailure'}] ->
              lager:error("CAS returned Proxy Failure~nCAS Response:~n~s", [Body]),
              error;
            El ->
              lager:error("Unexpected XML contents in response from CAS: ~p~nCAS Response:~n~s", [El, Body]),
              error
            end;
          #xmlElement{name = Name} ->
            lager:warning("Unexpected XML tag in response from CAS: ~s~nCAS Response:~n~s", [Name, Body]),
            retry;  %% Might be an error message instead of a CAS response, worth trying again
          El ->
            lager:warning("Unexpected XML contents in response from CAS: ~p~nCAS Response:~n~s", [El, Body]),
            retry  %% Might be an error message instead of a CAS response, worth trying again
          end
        end;
      {ok, {{_HTTPVersion, StatusCode, ReasonPhrase}, _Headers, Body}} ->
        lager:warning("Received HTTP ~b (~s) error from ~s with body:~n~s", [StatusCode, ReasonPhrase, ProxyURL, Body]),
        retry;
      {error, {failed_connect, [_, {_, _, timeout}]} = Reason} ->
        lager:warning("Timed out establishing connection to ~s : ~p", [ProxyURL, Reason]),
        retry;
      {error, {failed_connect, _} = Reason} ->
        lager:warning("Error establishing connection to ~s : ~p", [ProxyURL, Reason]),
        retry;
      {error, timeout} ->
        lager:warning("Timed out while retrieving ~s", [ProxyURL]),
        retry;
      {error, Reason} ->
        lager:warning("Error while retrieving ~s : ~p", [ProxyURL, Reason]),
        retry;
      ReplyInfo ->
        lager:error("Received unexpected ReplyInfo from httpc for ~s : ~p", [ProxyURL, ReplyInfo]),
        error
      end
    end
  end.

%% @doc Return the CAS Service Ticket associated with the specified Single Sign Out request body.
%% Returns 'not_sso' if the specified body does not appear to be a Single Sign Out request.  Returns
%% 'error' if the specified body appears to be a Single Sign Out request but parsing fails.
-spec parse_single_sign_out_request(Body) -> {ok, Ticket} | not_sso | error
  when Body::binary(), Ticket::binary().
parse_single_sign_out_request(Body) ->
  case catch parse_xml(Body) of
  {'EXIT', _Reason} -> not_sso;
  Doc ->
    case find_tag('LogoutRequest', [Doc]) of
    undefined -> not_sso;
    LogoutRequest ->
      case find_tag('SessionIndex', LogoutRequest#xmlElement.content) of
      #xmlElement{content = [#xmlText{value = Ticket}]} -> {ok, Ticket};
      _ -> error
      end
    end
  end.

%% @doc Extract the user name from the specified CAS authentication attributes.  Returns
%% 'not_authenticated' if the attributes indicate no CAS authentication.
-spec user(attributes()) -> not_authenticated | User when User::binary().
user(Attrs) ->
  case Attrs of
  not_authenticated -> not_authenticated;
  _ -> proplists:get_value(<<"user">>, Attrs)
  end.

%% @doc Extract the specified attribute the specified CAS authentication attributes.  Returns
%% 'not_authenticated' if the attributes indicate no CAS authentication, or 'undefined' if the
%% requested attribute was not returned by CAS.
-spec attribute(Key, attributes()) -> not_authenticated | Value | undefined
  when Key::binary(), Value::binary().
attribute(Key, Attrs) ->
  case Attrs of
  not_authenticated -> not_authenticated;
  _ -> proplists:get_value(Key, Attrs)
  end.



%%%=================================================================================================
%%% Internal CAS Utilities

%% @private
%% @doc Process a CAS response.
-spec process_cas_response(Ticket, Body, ConfigFun) -> {ok, attributes()} | retry | error
  when Ticket::binary(), Body::binary(), ConfigFun::config_get_fun().
process_cas_response(Ticket, Body, ConfigFun) ->
  case parse_cas_response(config(cas_protocol, ConfigFun), Body) of
  {ok, Attrs} ->
    Attrs1 = [{<<"ticket">>, Ticket} | Attrs],
    %% Verify "user" attribute
    case user(Attrs1) of
    undefined ->
      lager:error("No user identifier found in response from CAS~nCAS Response:~n~s~nCAS Attributes: ~p", [Body, Attrs1]),
      error;
    <<>> ->
      lager:error("Empty user identifier found in response from CAS~nCAS Response:~n~s~nCAS Attributes: ~p", [Body, Attrs1]),
      error;
    _ ->
      %% Verify proxy chain
      Result1 =
        case {config(allowed_proxy_chains, ConfigFun),
          proplists:get_all_values(<<"proxy">>, Attrs1)} of
        {_, []} -> ok;
        {undefined, _} ->
          lager:error("Received Proxy Chain from CAS when Proxy Ticket validation is disabled~nCAS Response:~n~s", [Body]),
          error;
        {any, _} -> ok;
        {AllowedChains, Chain} ->
          case lists:member(Chain, AllowedChains) of
          true -> ok;
          false ->
            lager:error("CAS Proxy Chain is not listed in 'allowed_proxy_chains': ~p", [Chain]),
            error
          end
        end,
      case Result1 of
      ok ->
        %% Retrieve PGT if necessary
        PGTattr = <<"proxyGrantingTicket">>,
        Result2 =
          case {config(pgt_callback_url, ConfigFun) =/= undefined, attribute(PGTattr, Attrs1)} of
          {false, undefined} -> {ok, Attrs1};
          {false, _} ->
            lager:warning("Ignoring unexpected proxyGrantingTicket in response from CAS~nCAS Response:~n~s", [Body]),
            {ok, proplists:delete(<<"proxyGrantingTicket">>, Attrs1)};
          {true, undefined} ->
            lager:warning("No proxyGrantingTicket in response from CAS~nCAS Response:~n~s", [Body]),
            retry;
          {true, PGTiou} ->
            case get_pgt(PGTiou) of
            undefined ->
              lager:warning("Did not receive PGT callback associated with response from CAS~nCAS Response:~n~s", [Body]),
              retry;
            PGT -> {ok, lists:keyreplace(PGTattr, 1, Attrs1, {PGTattr, PGT})}
            end
          end,
        case Result2 of
        {ok, Attrs2} ->
          lager:info("Successfully authenticated via CAS~nCAS Attributes: ~p", [Attrs2]),
          {ok, Attrs2};
        E -> E
        end;
      E -> E
      end
    end;
  E -> E
  end.

%% @private
%% @doc Parse a CAS response.
-spec parse_cas_response(Protocol, Body) -> {ok, attributes()} | retry | error
  when Protocol::atom(), Body::binary().
parse_cas_response(cas10, Body) ->
  case binary:split(Body, <<"\n">>, [global]) of
  [<<"yes">>, User, <<>>] ->
    {ok, [{<<"user">>, User}]};
  [<<"no">>, <<>>, <<>>] ->
    lager:error("CAS returned Authentication Failure"),
    error;
  _ ->
    lager:warning("Error parsing response from CAS~nCAS Response:~n~s", [Body]),
    retry  %% Might be an error message instead of a CAS response, worth trying again
  end;
parse_cas_response(cas20, Body) ->
  case catch parse_xml(Body) of
  {'EXIT', Reason} ->
    lager:warning("Error parsing response from CAS: ~p~nCAS Response:~n~s", [Reason, Body]),
    retry;  %% Might be an error message instead of a CAS response, worth trying again
  Doc ->
    case Doc of
    #xmlElement{name = 'cas:serviceResponse', content = RespContent} ->
      case RespContent of
      [#xmlElement{name = 'cas:authenticationSuccess', content = XMLAttrs}] ->
        {ok, lists:flatten(parse_cas20_attributes(XMLAttrs))};
      [#xmlElement{name = 'cas:authenticationFailure'}] ->
        lager:error("CAS returned Authentication Failure~nCAS Response:~n~s", [Body]),
        error;
      El ->
        lager:error("Unexpected XML contents in response from CAS: ~p~nCAS Response:~n~s", [El, Body]),
        error
      end;
    #xmlElement{name = Name} ->
      lager:warning("Unexpected XML tag in response from CAS: ~s~nCAS Response:~n~s", [Name, Body]),
      retry;  %% Might be an error message instead of a CAS response, worth trying again
    El ->
      lager:warning("Unexpected XML contents in response from CAS: ~p~nCAS Response:~n~s", [El, Body]),
      retry  %% Might be an error message instead of a CAS response, worth trying again
    end
  end;
parse_cas_response(saml11, Body) ->
  case catch parse_xml(Body) of
  {'EXIT', Reason} ->
    lager:warning("Error parsing response from CAS: ~p~nCAS Response:~n~s", [Reason, Body]),
    retry;  %% Might be an error message instead of a CAS response, worth trying again
  Doc ->
    case find_tag('Envelope', [Doc]) of
    undefined ->
      lager:warning("No Envelope tag found in response from CAS~nCAS Response:~n~s", [Body]),
      retry;  %% Might be an error message instead of a CAS response, worth trying again
    Envelope ->
      case find_tag('Body', Envelope#xmlElement.content) of
      undefined ->
        lager:error("No Body tag found in response from CAS~nCAS Response:~n~s", [Body]),
        error;
      BodyTag ->
        case find_tag('Response', BodyTag#xmlElement.content) of
        undefined ->
          lager:error("No Response tag found in response from CAS~nCAS Response:~n~s", [Body]),
          error;
        Response ->
          case find_tag('Status', Response#xmlElement.content) of
          undefined ->
            lager:error("No Status tag found in response from CAS~nCAS Response:~n~s", [Body]),
            error;
          Status ->
            case find_tag('StatusCode', Status#xmlElement.content) of
            undefined ->
              lager:error("No StatusCode tag found in response from CAS~nCAS Response:~n~s", [Body]),
              error;
            StatusCode ->
              case find_attr('Value', StatusCode#xmlElement.attributes) of
              undefined ->
                lager:error("No Value on StatusCode tag in response from CAS~nCAS Response:~n~s", [Body]),
                error;
              ValueAttr when not is_list(ValueAttr#xmlAttribute.value) ->
                lager:error("Invalid StatusCode tag in response from CAS: ~p~nCAS Response:~n~s", [ValueAttr, Body]),
                error;
              ValueAttr ->
                StatusGood =
                  case string:tokens(ValueAttr#xmlAttribute.value, ":") of
                  ["Success"] -> true;
                  [_NameSpace, "Success"] -> true;
                  _ -> false
                  end,
                case StatusGood of
                false ->
                  lager:error("CAS returned Authentication Failure~nCAS Response:~n~s", [Body]),
                  error;
                _ ->
                  case find_tag('Assertion', Response#xmlElement.content) of
                  undefined ->
                    lager:error("No Assertion tag in response from CAS~nCAS Response:~n~s", [Body]),
                    error;
                  Assertion ->
                    TimestampGood =
                      case find_tag('Conditions', Assertion#xmlElement.content) of
                      undefined -> true;
                      Conditions ->
                        CurSecs = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
                        NotBeforeGood =
                          case find_attr('NotBefore', Conditions#xmlElement.attributes) of
                          undefined -> true;
                          NotBefore when not is_list(NotBefore#xmlAttribute.value) ->
                            lager:warn("Invalid NotBefore attribute in response from CAS: ~p~nCAS Response:~n~s", [NotBefore, Body]),
                            true;
                          NotBefore ->
                            <<Year1:4/binary,"-",Month1:2/binary,"-",Day1:2/binary,"T",
                              Hour1:2/binary,":",Minute1:2/binary,":",Second1:2/binary,
                              _Rem1/binary>> = list_to_binary(NotBefore#xmlAttribute.value),
                            NotBeforeSecs = calendar:datetime_to_gregorian_seconds(
                              {{binary_to_integer(Year1), binary_to_integer(Month1), binary_to_integer(Day1)},
                               {binary_to_integer(Hour1), binary_to_integer(Minute1), binary_to_integer(Second1)}}),
                            CurSecs >= NotBeforeSecs
                          end,
                        NotAfterGood =
                          case find_attr('NotOnOrAfter', Conditions#xmlElement.attributes) of
                          undefined -> true;
                          NotAfter when not is_list(NotAfter#xmlAttribute.value) ->
                            lager:warn("Invalid NotAfter attribute in response from CAS: ~p~nCAS Response:~n~s", [NotAfter, Body]),
                            true;
                          NotAfter ->
                            <<Year2:4/binary,"-",Month2:2/binary,"-",Day2:2/binary,"T",
                              Hour2:2/binary,":",Minute2:2/binary,":",Second2:2/binary,
                              _Rem2/binary>> = list_to_binary(NotAfter#xmlAttribute.value),
                            NotAfterSecs = calendar:datetime_to_gregorian_seconds(
                              {{binary_to_integer(Year2), binary_to_integer(Month2), binary_to_integer(Day2)},
                               {binary_to_integer(Hour2), binary_to_integer(Minute2), binary_to_integer(Second2)}}),
                            CurSecs < NotAfterSecs
                          end,
                        NotBeforeGood andalso NotAfterGood
                      end,
                    case TimestampGood of
                    false ->
                      lager:error("Bad timestamp in response from CAS~nCAS Response:~n~s", [Body]),
                      error;
                    true ->
                      case find_tag('AuthenticationStatement', Assertion#xmlElement.content) of
                      undefined ->
                        lager:error("No AuthenticationStatement tag in response from CAS~nCAS Response:~n~s", [Body]),
                        error;
                      AuthenticationStatement ->
                        case find_attr('AuthenticationMethod', AuthenticationStatement#xmlElement.attributes) of
                        undefined ->
                          lager:error("No AuthenticationMethod on AuthenticationStatement tag in response from CAS~nCAS Response:~n~s", [Body]),
                          error;
                        MethodAttr when not is_list(MethodAttr#xmlAttribute.value) ->
                          lager:error("Invalid MethodAttr attribute in response from CAS: ~p~nCAS Response:~n~s", [MethodAttr, Body]),
                          error;
                        MethodAttr ->
                          Method = {<<"AuthenticationMethod">>, list_to_binary(MethodAttr#xmlAttribute.value)},
                          case find_tag('AttributeStatement', Assertion#xmlElement.content) of
                          undefined ->
                            lager:error("No AttributeStatement tag in response from CAS~nCAS Response:~n~s", [Body]),
                            error;
                          AttributeStatement ->
                            Attrs = parse_saml11_attributes(AttributeStatement#xmlElement.content),
                            {ok, [Method | Attrs]}
                          end
                        end
                      end
                    end
                  end
                end
              end
            end
          end
        end
      end
    end
  end.

%% @private
%% @doc Parse XML.
-spec parse_xml(XML::binary()) -> #xmlElement{}.
parse_xml(XML) ->
  {Doc, _Rest} = xmerl_scan:string(binary_to_list(XML), [{space, normalize}, {comments, false}]),
  strip_empty_xmltext(Doc).
strip_empty_xmltext(#xmlElement{content = []} = El) -> El;
strip_empty_xmltext(#xmlElement{content = Children} = El) ->
  Fun =
    fun
    (#xmlElement{} = ChildEl) -> {true, strip_empty_xmltext(ChildEl)};
    (#xmlText{value = " "}) -> false;
    (#xmlText{}) -> true;
    (_) -> false
    end,
  El#xmlElement{content = lists:filtermap(Fun, Children)}.

%% @private
%% @doc Find an xmlElement with the specified name (without namespace) in the specified list.  Does
%% not recurse through child elements; only top-level elements are checked.  Returns 'undefined' if
%% an xmlElement with the specified name is not found.
-spec find_tag(Name::atom(), Elements::list(any())) -> undefined | #xmlElement{}.
find_tag(_Name, []) -> undefined;
find_tag(Name, [#xmlElement{name = Tag} = El | Rest]) ->
  NameStr = atom_to_list(Name),
  case string:tokens(atom_to_list(Tag), ":") of
  [NameStr] -> El;
  [_NameSpace, NameStr] -> El;
  _ -> find_tag(Name, Rest)
  end;
find_tag(Name, [_El | Rest]) -> find_tag(Name, Rest).

%% @private
%% @doc Find an xmlAttribute with the specified name in the specified list.  Returns 'undefined' if
%% an xmlAttribute with the specified name is not found.
-spec find_attr(Name::atom(), Attrs::list(#xmlAttribute{})) -> undefined | #xmlAttribute{}.
find_attr(_Name, []) -> undefined;
find_attr(Name, [#xmlAttribute{name = Name} = El | _Rest]) -> El;
find_attr(Name, [_El | Rest]) -> find_attr(Name, Rest).

%% @private
%% @doc Recursively parse attributes in a CAS 2.0 response.
-spec parse_cas20_attributes(list(#xmlElement{})) -> iolist().
parse_cas20_attributes(XMLAttrs) ->
  Fun =
    fun
    (#xmlElement{name = Tag, content = [#xmlText{value = Value}]}) ->
      case string:tokens(atom_to_list(Tag), ":") of
      [Name] -> {list_to_binary(Name), list_to_binary(string:strip(Value))};
      [_NameSpace, Name] -> {list_to_binary(Name), list_to_binary(string:strip(Value))}
      end;
    (#xmlElement{name = Tag, content = []}) ->
      case string:tokens(atom_to_list(Tag), ":") of
      [Name] -> {list_to_binary(Name), <<>>};
      [_NameSpace, Name] -> {list_to_binary(Name), <<>>}
      end;
    (#xmlElement{content = Children}) ->
      parse_cas20_attributes(Children)
    end,
  lists:map(Fun, XMLAttrs).

%% @private
%% @doc Parse children of a SAML 1.1 AttributeStatement tag.
-spec parse_saml11_attributes(list(any())) -> attributes().
parse_saml11_attributes(XMLAttrs) ->
  Fun =
    fun
    (#xmlElement{name = RawTag, attributes = Attrs, content = Children}) ->
      Tag =
        case string:tokens(atom_to_list(RawTag), ":") of
        [Name] -> list_to_binary(Name);
        [_NameSpace, Name] -> list_to_binary(Name)
        end,
      case Tag of
      <<"Subject">> ->
        case find_tag('NameIdentifier', Children) of
        #xmlElement{content = [#xmlText{value = User}]} -> {true, {<<"user">>, list_to_binary(string:strip(User))}};
        _ -> false
        end;
      <<"Attribute">> ->
        case find_attr('AttributeName', Attrs) of
        #xmlAttribute{value = AttrName} ->
          AttrFun =
            fun
            (#xmlElement{name = RawTag2, content = [#xmlText{value = Value}]}) ->
              case string:tokens(atom_to_list(RawTag2), ":") of
              ["AttributeValue"] -> {true, string:strip(Value)};
              [_NameSpace2, "AttributeValue"] -> {true, string:strip(Value)};
              _ -> false
              end;
            (_) -> false
            end,
          AttrVal = string:join(lists:filtermap(AttrFun, Children), ","),
          {true, {list_to_binary(AttrName), list_to_binary(AttrVal)}};
        _ -> false
        end;
      _ -> false
      end;
    (_) -> false
    end,
  lists:filtermap(Fun, XMLAttrs).

%% @private
%% @doc Retrieve the PGT associated with a PGT-IOU.
-spec get_pgt(PGTiou) -> undefined | PGT when PGTiou::binary(), PGT::binary().
get_pgt(PGTiou) ->
  case ets:lookup(?MODULE, PGTiou) of
  [#pgt_iou{pgt = PGT}] -> ets:delete(?MODULE, PGTiou), PGT;
  _ -> undefined
  end.

%% @private
%% @doc Delete any unclaimed PGTs.
-spec clean_unclaimed_pgts() -> ok.
clean_unclaimed_pgts() ->
  ets:safe_fixtable(?MODULE, true),
  clean_pgt(ets:first(?MODULE)),
  ets:safe_fixtable(?MODULE, false),
  ok.
clean_pgt('$end_of_table') -> ok;
clean_pgt(Key) ->
  [#pgt_iou{iou = PGTiou, pgt = PGT, timestamp = Timestamp}] = ets:lookup(?MODULE, Key),
  ExpiresAt = Timestamp + 120,  %% Time out after 120 seconds
  Now = current_time(),
  if
  ExpiresAt < Now ->
    lager:info("Deleting unclaimed PGT ~s associated with PGT-IOU ~s from CAS", [PGT, PGTiou]),
    ets:delete(?MODULE, Key);
  true -> continue
  end,
  clean_pgt(ets:next(?MODULE, Key)).



%%%=================================================================================================
%%% Misc Utilities

%% @doc URL encode the specified binary string.
-spec url_encode(binary()) -> binary().
url_encode(S) -> list_to_binary(http_uri:encode(binary_to_list(S))).

%% @doc Get the current time in seconds since the Epoch.
-spec current_time() -> Seconds::integer().
current_time() ->
  {MegaSecs, Secs, _} = os:timestamp(),
  %% Apparently MegaSecs is from when Erlang couldn't handle integers that big
  (MegaSecs * 1000000) + Secs.



%%%=================================================================================================
%%% OTP Application API

start() ->
  ok = application:start(cas_client_core).

start(_Type, _Args) ->
  case cas_client_core_config:validate(undefined) of
  {error, Message} ->
    lager:error("~s", [Message]),
    throw({error, Message});
  _ -> ok
  end,
  %% Prepare the PGT storage table
  case ets:info(?MODULE) of
  undefined -> ets:new(?MODULE, [set, public, named_table, {keypos, 2}, {write_concurrency, true}]);
  _ -> ok
  end,
  %% Prepare a configuration profile in the http client and set profile options
  %% See httpc_request_httpoptions() below for options that must be configured per-request
  {ok, _PID} = inets:start(httpc, [{profile, ?MODULE}]),
  ok = httpc:set_options(httpc_profile_options(), ?MODULE),
  {ok, self()}.

stop(_Args) ->
  ets:delete(?MODULE),
  inets:stop(httpc, ?MODULE).



%%%=================================================================================================
%%% httpc Abstractions

%% @private
%% @doc Return the configured httpc_options value merged with module defaults.
%% See http://erlang.org/doc/man/httpc.html#set_options-1
-spec httpc_profile_options() -> list({atom(), any()}).
httpc_profile_options() ->
  Defaults = [{max_sessions, 100}, {keep_alive_timeout, 30000}],
  Config = config(httpc_options, undefined),
  lists:ukeymerge(1, lists:ukeysort(1, Config), lists:ukeysort(1, Defaults)).

%% @private
%% @doc Return the configured httpc_httpoptions and ssl_options values merged with module defaults.
%% See http://erlang.org/doc/man/httpc.html#request-4 and http://erlang.org/doc/man/ssl.html
-spec httpc_request_httpoptions(ConfigFun) -> list({atom(), any()})
  when ConfigFun::config_get_fun().
httpc_request_httpoptions(ConfigFun) ->
  SSLDefaults = [{secure_renegotiate, true}, {depth, 10}],
  SSLConfig = config(ssl_options, ConfigFun),
  SSL = lists:ukeymerge(1, lists:ukeysort(1, SSLConfig), lists:ukeysort(1, SSLDefaults)),
  HTTPDefaults = [{connect_timeout, 10000}, {timeout, 10000}, {ssl, SSL}, {autoredirect, false}],
  HTTPConfig = config(httpc_httpoptions, ConfigFun),
  lists:ukeymerge(1, lists:ukeysort(1, HTTPConfig), lists:ukeysort(1, HTTPDefaults)).

%% @private
%% @doc Return the specified httpc request options merged with module defaults.
%% See http://erlang.org/doc/man/httpc.html#request-4
-spec httpc_request_options(list({atom(), any()}), ConfigFun) -> list({atom(), any()})
  when ConfigFun::config_get_fun().
httpc_request_options(Options, _ConfigFun) ->
  Defaults = [{body_format, binary}],
  lists:ukeymerge(1, lists:ukeysort(1, Options), lists:ukeysort(1, Defaults)).

%% @private
%% @doc Return the specified httpc request Headers merged with module defaults.
-spec httpc_request_headers(list({string(), string()}), ConfigFun) -> list({string(), string()})
  when ConfigFun::config_get_fun().
httpc_request_headers(Headers, _ConfigFun) ->
  Headers.
  %Defaults = [{"Accept", "text/xml"}],
  %lists:ukeymerge(1, lists:ukeysort(1, Headers), lists:ukeysort(1, Defaults)).

%% @doc Convenience wrapper for httpc:request().  Accepts binary URLs and injects module default
%% options and/or configured options for this module.
-spec httpc_request(Method, Request, Options, ConfigFun) ->
  {ok, Response::any()} | {error, Error::any()}
  when Method::atom(), Request::any(), Options::list({atom(), any()}), ConfigFun::config_get_fun().
httpc_request(Method, Request, Options, ConfigFun) ->
  NewRequest = case Request of
    {URL, Headers} when is_binary(URL) ->
      {binary_to_list(URL), httpc_request_headers(Headers, ConfigFun)};
    {URL, Headers, CT, Body} when is_binary(URL) ->
      {binary_to_list(URL), httpc_request_headers(Headers, ConfigFun), CT, Body};
    Other -> Other
  end,
  httpc:request(Method, NewRequest, httpc_request_httpoptions(ConfigFun),
    httpc_request_options(Options, ConfigFun), ?MODULE).
