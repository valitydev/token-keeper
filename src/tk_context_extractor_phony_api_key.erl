-module(tk_context_extractor_phony_api_key).
-behaviour(tk_context_extractor).

-export([extract_context/2]).

%%

-type opts() :: #{
    metadata_mappings := #{
        party_id := binary()
    }
}.

-export_type([opts/0]).

%%

-define(CLAIM_PARTY_ID, <<"sub">>).

%% API functions

-spec extract_context(tk_token:token_data(), opts()) -> tk_context_extractor:extracted_context() | undefined.
extract_context(#{id := TokenID, payload := Payload} = TokenData, Opts) ->
    case extract_party_data(Payload) of
        {ok, PartyID} ->
            case check_blacklist(PartyID, TokenData) of
                ok ->
                    create_context_and_metadata(TokenID, PartyID, Opts);
                {error, blacklisted} ->
                    _ = logger:warning("phony_api_key context was extract, but it blacklisted for user id: ~p", [
                        PartyID
                    ]),
                    undefined
            end;
        {error, Reason} ->
            _ = logger:warning("Could not extract phony_api_key context, reason: ~p", [Reason]),
            undefined
    end.

%%

check_blacklist(PartyID, #{authority_id := AuthorityID}) ->
    case tk_blacklist:is_user_blacklisted(PartyID, AuthorityID) of
        false ->
            ok;
        true ->
            {error, blacklisted}
    end.

create_context_and_metadata(TokenID, PartyID, Opts) ->
    {
        create_context(TokenID, PartyID),
        wrap_metadata(
            create_metadata(PartyID),
            Opts
        )
    }.

extract_party_data(#{
    ?CLAIM_PARTY_ID := PartyID
}) ->
    {ok, PartyID};
extract_party_data(_) ->
    {error, {missing, ?CLAIM_PARTY_ID}}.

create_context(TokenID, PartyID) ->
    bouncer_context_helpers:add_auth(
        #{
            method => <<"ApiKeyToken">>,
            token => #{id => TokenID},
            scope => [#{party => #{id => PartyID}}]
        },
        bouncer_context_helpers:empty()
    ).

create_metadata(PartyID) ->
    #{party_id => PartyID}.

wrap_metadata(Metadata, Opts) ->
    Mappings = maps:get(metadata_mappings, Opts),
    tk_utils:remap(genlib_map:compact(Metadata), Mappings).
