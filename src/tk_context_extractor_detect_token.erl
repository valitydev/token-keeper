-module(tk_context_extractor_detect_token).
-behaviour(tk_context_extractor).

%% Behaviour

-export([extract_context/2]).

%% API Types

-type opts() :: #{
    user_session_token_opts := tk_context_extractor_user_session_token:opts(),
    user_session_token_origins := list(binary())
}.

-export_type([opts/0]).

%% Behaviour

-spec extract_context(tk_token:token_data(), opts()) -> tk_context_extractor:extracted_context() | undefined.
extract_context(VerifiedToken, Opts) ->
    TokenType = determine_token_type(get_source_context(VerifiedToken), Opts),
    tk_context_extractor:extract_context(make_method_opts(TokenType, Opts), VerifiedToken).

%% Internal functions

get_source_context(#{source_context := SourceContext}) ->
    SourceContext.

determine_token_type(#{request_origin := Origin}, #{user_session_token_origins := UserTokenOrigins}) ->
    case lists:member(Origin, UserTokenOrigins) of
        true ->
            user_session_token;
        false ->
            phony_api_key
    end;
determine_token_type(#{}, _UserTokenOrigins) ->
    phony_api_key.

make_method_opts(TokenType, Opts) ->
    {TokenType, get_opts(TokenType, Opts)}.

get_opts(user_session_token, #{user_session_token_opts := Opts}) ->
    Opts;
get_opts(phony_api_key, _) ->
    undefined.
