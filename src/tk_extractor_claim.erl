-module(tk_extractor_claim).
-behaviour(tk_context_extractor).

-include_lib("token_keeper_proto/include/tk_context_thrift.hrl").

-export([get_context/2]).

%%

-type extractor_opts() :: #{
    metadata_ns := binary()
}.

-export_type([extractor_opts/0]).

%% API functions

-spec get_context(tk_token_jwt:t(), extractor_opts()) -> tk_context_extractor:extracted_context() | undefined.
get_context(Token, ExtractorOpts) ->
    % TODO
    % We deliberately do not handle decoding errors here since we extract claims from verified
    % tokens only, hence they must be well-formed here.
    Claims = tk_token_jwt:get_claims(Token),
    case get_claim(Claims) of
        {ok, ClaimFragment} ->
            {ClaimFragment, wrap_metadata(get_metadata(Token), ExtractorOpts)};
        undefined ->
            undefined
    end.

%% Internal functions

get_metadata(Token) ->
    %% @TEMP: This is a temporary hack.
    %% When some external services will stop requiring woody user identity to be present it must be removed too
    case tk_token_jwt:get_subject_id(Token) of
        UserID when UserID =/= undefined ->
            #{<<"party_id">> => UserID};
        undefined ->
            undefined
    end.

wrap_metadata(undefined, _ExtractorOpts) ->
    undefined;
wrap_metadata(Metadata, ExtractorOpts) ->
    MetadataNS = maps:get(metadata_ns, ExtractorOpts),
    #{MetadataNS => Metadata}.

-define(CLAIM_BOUNCER_CTX, <<"bouncer_ctx">>).
-define(CLAIM_CTX_TYPE, <<"ty">>).
-define(CLAIM_CTX_CONTEXT, <<"ct">>).

-define(CLAIM_CTX_TYPE_V1_THRIFT_BINARY, <<"v1_thrift_binary">>).

-type claim() :: tk_token_jwt:claim().
-type claims() :: tk_token_jwt:claims().

-spec get_claim(claims()) ->
    {ok, tk_context_extractor:context_fragment()}
    | {error, {unsupported, claim()} | {malformed, binary()}}
    | undefined.
get_claim(Claims) ->
    case maps:get(?CLAIM_BOUNCER_CTX, Claims, undefined) of
        Claim when Claim /= undefined ->
            decode_claim(Claim);
        undefined ->
            undefined
    end.

-spec decode_claim(claim()) ->
    {ok, tk_context_extractor:context_fragment()} | {error, {unsupported, claim()} | {malformed, binary()}}.
decode_claim(#{
    ?CLAIM_CTX_TYPE := ?CLAIM_CTX_TYPE_V1_THRIFT_BINARY,
    ?CLAIM_CTX_CONTEXT := Content
}) ->
    try
        {ok,
            {encoded_context_fragment, #bctx_ContextFragment{
                type = v1_thrift_binary,
                content = base64:decode(Content)
            }}}
    catch
        % NOTE
        % The `base64:decode/1` fails in unpredictable ways.
        error:_ ->
            {error, {malformed, Content}}
    end;
decode_claim(Ctx) ->
    {error, {unsupported, Ctx}}.
