-module(tk_blacklist).

-behaviour(supervisor).

%% API

-export([is_blacklisted/2]).
-export([is_user_blacklisted/2]).

%% Supervisor callbacks

-export([init/1]).
-export([child_spec/1]).

%%

-type options() :: #{
    %% Path to blacklist file
    path => binary()
}.

-export_type([options/0]).

%%

-define(TAB, ?MODULE).
-define(USER_TAB, user_blacklist).

%%

-spec child_spec(options()) -> supervisor:child_spec() | no_return().
child_spec(Options) ->
    #{
        id => ?MODULE,
        start => {supervisor, start_link, [?MODULE, Options]},
        type => supervisor
    }.

-spec is_blacklisted(tk_token:token_id(), tk_token:authority_id()) -> boolean().
is_blacklisted(TokenID, AuthorityID) ->
    check_entry(?TAB, {AuthorityID, TokenID}).

-spec is_user_blacklisted(binary(), tk_token:authority_id()) -> boolean().
is_user_blacklisted(UserID, AuthorityID) ->
    check_entry(?USER_TAB, {AuthorityID, UserID}).

%%

-spec init(options()) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init(Options) ->
    _ = init_tab(?TAB),
    _ = init_tab(?USER_TAB),
    _ = load_blacklist_conf(maps:get(path, Options, undefined)),
    {ok, {#{}, []}}.

init_tab(Name) ->
    ets:new(Name, [set, protected, named_table, {read_concurrency, true}]).

-define(ENTRIES_KEY, "entries").
-define(USER_ENTRIES_KEY, "user_entries").

load_blacklist_conf(undefined) ->
    _ = logger:warning("No token blacklist file specified! Blacklisting functionality will be disabled."),
    ok;
load_blacklist_conf(Filename) ->
    [Mappings] = yamerl_constr:file(Filename),
    Entries = process_entries(proplists:get_value(?ENTRIES_KEY, Mappings)),
    put_entires(?TAB, Entries),
    UserEntries = process_entries(proplists:get_value(?USER_ENTRIES_KEY, Mappings)),
    put_entires(?USER_TAB, UserEntries).

process_entries(Entries) ->
    lists:foldl(
        fun({AuthorityID, IDs}, Acc) ->
            Acc ++ [make_ets_entry(AuthorityID, ID) || ID <- IDs]
        end,
        [],
        Entries
    ).

make_ets_entry(AuthorityID, ID) ->
    {{list_to_binary(AuthorityID), list_to_binary(ID)}, true}.

%%

put_entires(Name, Entries) ->
    ets:insert_new(Name, Entries).

check_entry(Name, Key) ->
    case ets:lookup(Name, Key) of
        [_Entry] -> true;
        [] -> false
    end.
