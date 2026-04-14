-module(tk_context_extractor).

%% Behaviour

-callback extract_context(token_data(), opts()) -> extracted_context() | undefined.

%% API functions

-export([extract_context/2]).

%% API Types

-type methods() :: [method_opts()].
-type method_opts() ::
    {detect_token, tk_context_extractor_detect_token:opts()}
    | {user_session_token, tk_context_extractor_user_session_token:opts()}.
-type extracted_context() :: {context_fragment(), tk_authdata:metadata() | undefined}.

-export_type([methods/0]).
-export_type([method_opts/0]).
-export_type([extracted_context/0]).

%% Internal types

-type token_data() :: tk_token:token_data().
-type context_fragment() :: bouncer_context_helpers:context_fragment().
-type opts() ::
    tk_context_extractor_detect_token:opts()
    | tk_context_extractor_user_session_token:opts().

%% API functions

-spec extract_context(method_opts(), token_data()) -> extracted_context() | undefined.
extract_context({detect_token, Opts}, TokenData) ->
    tk_context_extractor_detect_token:extract_context(TokenData, Opts);
extract_context({phony_api_key, _}, _TokenData) ->
    %% NOTE This clause is left behind as a fallback placeholder in place of
    %% now-removed phony api key detection.
    undefined;
extract_context({user_session_token, Opts}, TokenData) ->
    tk_context_extractor_user_session_token:extract_context(TokenData, Opts).
