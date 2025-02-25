-module(token_keeper_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-include_lib("token_keeper_proto/include/tk_token_keeper_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_ctx_thrift.hrl").

-include_lib("bouncer_proto/include/bouncer_base_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_ctx_v1_thrift.hrl").

-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).
-export([init_per_testcase/2]).
-export([end_per_testcase/2]).

-export([authenticate_invalid_token_type_fail/1]).
-export([authenticate_invalid_token_key_fail/1]).
-export([authenticate_no_payload_claims_fail/1]).
-export([authenticate_user_session_token_no_payload_claims_fail/1]).
-export([authenticate_phony_api_key_token_ok/1]).
-export([authenticate_user_session_token_ok/1]).
-export([authenticate_user_session_token_w_exp_ok/1]).
-export([authenticate_user_session_token_no_exp_fail/1]).
-export([authenticate_user_session_token_w_resource_access/1]).
-export([authenticate_blacklisted_jti_fail/1]).
-export([authenticate_non_blacklisted_jti_ok/1]).
-export([authenticate_blacklisted_user_fail/1]).
-export([authenticate_ephemeral_claim_token_ok/1]).
-export([issue_ephemeral_token_ok/1]).
-export([authenticate_offline_token_not_found_fail/1]).
-export([authenticate_offline_token_revoked_fail/1]).
-export([authenticate_offline_token_ok/1]).
-export([issue_offline_token_ok/1]).
-export([issue_duplicate_offline_token_fail/1]).
-export([get_authdata_by_id_ok/1]).
-export([get_authdata_by_id_not_found_fail/1]).
-export([revoke_authdata_by_id_ok/1]).
-export([revoke_authdata_by_id_not_found_fail/1]).

-type config() :: [{atom(), any()}].
-type group_name() :: atom().
-type test_case_name() :: atom().

-define(CONFIG(Key, C), (element(2, lists:keyfind(Key, 1, C)))).
-define(UPDATE_CONFIG(Key, C, F), lists:keyreplace(Key, 1, C, {Key, F(?CONFIG(Key, C))})).

%%

-define(TOKEN_SOURCE_CONTEXT, ?TOKEN_SOURCE_CONTEXT(<<"http://spanish.inquisition">>)).
-define(TOKEN_SOURCE_CONTEXT(SourceURL), #token_keeper_TokenSourceContext{request_origin = SourceURL}).
-define(USER_TOKEN_SOURCE, <<"https://dashboard.rbk.money">>).

-define(META_PARTY_ID, <<"test.rbkmoney.party.id">>).
-define(META_USER_ID, <<"test.rbkmoney.user.id">>).
-define(META_USER_EMAIL, <<"test.rbkmoney.user.email">>).
-define(META_USER_REALM, <<"test.rbkmoney.user.realm">>).
-define(META_CAPI_CONSUMER, <<"test.rbkmoney.capi.consumer">>).

-define(TK_AUTHORITY_KEYCLOAK, <<"test.rbkmoney.keycloak">>).
-define(TK_AUTHORITY_APIKEYMGMT, <<"test.rbkmoney.apikeymgmt">>).
-define(TK_AUTHORITY_CAPI, <<"test.rbkmoney.capi">>).

-define(TK_KEY_KEYCLOAK, <<"test.rbkmoney.key.keycloak">>).
-define(TK_KEY_APIKEYMGMT, <<"test.rbkmoney.key.apikeymgmt">>).
-define(TK_KEY_CAPI, <<"test.rbkmoney.key.capi">>).

-define(TK_RESOURCE_DOMAIN, <<"test-domain">>).

%%

-spec all() -> [{group, group_name()}].

all() ->
    [
        {group, external_detect_token},
        {group, blacklist},
        {group, ephemeral},
        {group, offline_machinegun},
        {group, offline_progressor},
        {group, offline_hybrid}
    ].

-spec groups() -> [{group_name(), list(), [test_case_name()]}].
groups() ->
    [
        {external_detect_token, [parallel], [
            authenticate_invalid_token_type_fail,
            authenticate_invalid_token_key_fail,
            authenticate_no_payload_claims_fail,
            authenticate_user_session_token_no_payload_claims_fail,
            authenticate_phony_api_key_token_ok,
            authenticate_user_session_token_ok,
            authenticate_user_session_token_w_exp_ok,
            authenticate_user_session_token_no_exp_fail,
            authenticate_user_session_token_w_resource_access
        ]},
        {ephemeral, [parallel], [
            authenticate_invalid_token_type_fail,
            authenticate_invalid_token_key_fail,
            authenticate_no_payload_claims_fail,
            authenticate_ephemeral_claim_token_ok,
            issue_ephemeral_token_ok
        ]},
        {offline_machinegun, [], [{group, offline}]},
        {offline_progressor, [], [{group, offline}]},
        {offline_hybrid, [], [{group, offline}]},
        {offline, [parallel], [
            authenticate_invalid_token_type_fail,
            authenticate_invalid_token_key_fail,
            authenticate_no_payload_claims_fail,
            authenticate_offline_token_not_found_fail,
            authenticate_offline_token_revoked_fail,
            authenticate_offline_token_ok,
            issue_offline_token_ok,
            issue_duplicate_offline_token_fail,
            get_authdata_by_id_ok,
            get_authdata_by_id_not_found_fail,
            revoke_authdata_by_id_ok,
            revoke_authdata_by_id_not_found_fail
        ]},
        {blacklist, [parallel], [
            authenticate_blacklisted_jti_fail,
            authenticate_non_blacklisted_jti_ok,
            authenticate_blacklisted_user_fail
        ]}
    ].

-spec init_per_suite(config()) -> config().
init_per_suite(C) ->
    Apps =
        genlib_app:start_application(woody) ++
            genlib_app:start_application_with(scoper, [
                {storage, scoper_storage_logger}
            ]),
    [{suite_apps, Apps} | C].

-spec end_per_suite(config()) -> ok.
end_per_suite(C) ->
    genlib_app:stop_unload_applications(?CONFIG(suite_apps, C)).
% @TODO Pending configurator
-spec init_per_group(group_name(), config()) -> config().
init_per_group(external_detect_token = Name, C) ->
    AuthenticatorPath = <<"/v2/authenticator">>,
    C0 = start_keeper([
        {authenticator, #{
            service => #{
                path => AuthenticatorPath
            },
            authorities => #{
                ?TK_AUTHORITY_KEYCLOAK =>
                    #{
                        sources => [extract_method_detect_token()]
                    }
            }
        }},
        {tokens, #{
            jwt => #{
                authority_bindings => #{
                    ?TK_KEY_KEYCLOAK => ?TK_AUTHORITY_KEYCLOAK
                },
                keyset => #{
                    ?TK_KEY_KEYCLOAK => #{
                        source => {pem_file, get_filename("keys/local/public.pem", C)}
                    }
                }
            }
        }}
    ]),
    ServiceUrls = #{
        token_authenticator => mk_url(AuthenticatorPath)
    },
    [{groupname, Name}, {service_urls, ServiceUrls} | C0 ++ C];
init_per_group(blacklist = Name, C) ->
    AuthenticatorPath = <<"/v2/authenticator">>,
    C0 = start_keeper([
        {authenticator, #{
            service => #{
                path => AuthenticatorPath
            },
            authorities => #{
                <<"blacklisting_authority">> =>
                    #{
                        sources => [extract_method_detect_token()]
                    },
                ?TK_AUTHORITY_CAPI =>
                    #{
                        sources => [extract_method_detect_token()]
                    }
            }
        }},
        {tokens, #{
            jwt => #{
                authority_bindings => #{
                    <<"blacklisting_authority.key">> => <<"blacklisting_authority">>,
                    ?TK_KEY_CAPI => ?TK_AUTHORITY_CAPI
                },
                keyset => #{
                    <<"blacklisting_authority.key">> => #{
                        source => {pem_file, get_filename("keys/local/private.pem", C)}
                    },
                    ?TK_KEY_CAPI => #{
                        source => {pem_file, get_filename("keys/secondary/private.pem", C)}
                    }
                }
            }
        }},
        {blacklist, #{
            path => get_filename("blacklisted_keys.yaml", C)
        }}
    ]),
    ServiceUrls = #{
        token_authenticator => mk_url(AuthenticatorPath)
    },
    [{groupname, Name}, {service_urls, ServiceUrls} | C0 ++ C];
init_per_group(ephemeral = Name, C) ->
    AuthenticatorPath = <<"/v2/authenticator">>,
    AuthorityPath = <<"/v2/authority/com.rbkmoney.access.capi">>,
    C0 = start_keeper([
        {authenticator, #{
            service => #{
                path => AuthenticatorPath
            },
            authorities => #{
                ?TK_AUTHORITY_CAPI => #{
                    sources => [
                        {claim, #{}}
                    ]
                }
            }
        }},
        {authorities, #{
            ?TK_AUTHORITY_CAPI =>
                #{
                    service => #{
                        path => AuthorityPath
                    },
                    type =>
                        {ephemeral, #{
                            token => #{
                                type => jwt
                            }
                        }}
                }
        }},
        {tokens, #{
            jwt => #{
                authority_bindings => #{
                    ?TK_KEY_CAPI => ?TK_AUTHORITY_CAPI
                },
                keyset => #{
                    ?TK_KEY_CAPI => #{
                        source => {pem_file, get_filename("keys/local/private.pem", C)}
                    }
                }
            }
        }}
    ]),
    ServiceUrls = #{
        token_authenticator => mk_url(AuthenticatorPath),
        {token_ephemeral_authority, ?TK_AUTHORITY_CAPI} => mk_url(AuthorityPath)
    },
    [{groupname, Name}, {service_urls, ServiceUrls} | C0 ++ C];
init_per_group(offline_machinegun = Name, C) ->
    init_for_offline(Name, machinegun, C);
init_per_group(offline_progressor = Name, C0) ->
    C1 = init_for_offline(Name, progressor, C0),
    init_with_progressor(C1);
init_per_group(offline_hybrid = Name, C0) ->
    C1 = init_for_offline(Name, hybrid, C0),
    init_with_progressor(C1);
init_per_group(offline = _Name, C) ->
    C.

init_with_progressor(C) ->
    NewApps =
        genlib_app:start_application_with(
            epg_connector,
            [
                {databases, #{
                    default_db => #{
                        host => "postgres",
                        port => 5432,
                        database => "progressor_db",
                        username => "progressor",
                        password => "progressor"
                    }
                }},
                {pools, #{
                    default_pool => #{
                        database => default_db,
                        size => 30
                    }
                }}
            ]
        ) ++
            genlib_app:start_application_with(
                progressor,
                [
                    {call_wait_timeout, 20},
                    {defaults, #{
                        storage => #{
                            client => prg_pg_backend,
                            options => #{
                                pool => default_pool
                            }
                        },
                        retry_policy => #{
                            initial_timeout => 5,
                            backoff_coefficient => 1.0,
                            %% seconds
                            max_timeout => 180,
                            max_attempts => 3,
                            non_retryable_errors => []
                        },
                        task_scan_timeout => 1,
                        worker_pool_size => 100,
                        process_step_timeout => 30
                    }},
                    {namespaces, #{
                        'apikeymgmt' => #{
                            processor => #{
                                client => machinery_prg_backend,
                                options => #{
                                    namespace => 'apikeymgmt',
                                    handler => {tk_storage_machinegun, #{}},
                                    schema => tk_storage_machinegun_schema
                                }
                            }
                        }
                    }}
                ]
            ),
    ?UPDATE_CONFIG(keeper_apps, C, fun(Apps) -> Apps ++ NewApps end).

init_for_offline(Name, MachineryMode, C) ->
    AuthenticatorPath = <<"/v2/authenticator">>,
    AuthorityPath = <<"/v2/authority/com.rbkmoney.apikemgmt">>,
    C0 = start_keeper([
        {authenticator, #{
            service => #{
                path => AuthenticatorPath
            },
            authorities => #{
                ?TK_AUTHORITY_APIKEYMGMT =>
                    #{
                        sources => [
                            {storage, #{
                                name => ?TK_AUTHORITY_APIKEYMGMT
                            }}
                        ]
                    }
            }
        }},
        {authorities, #{
            ?TK_AUTHORITY_APIKEYMGMT =>
                #{
                    service => #{
                        path => AuthorityPath
                    },
                    type =>
                        {offline, #{
                            token => #{
                                type => jwt
                            },
                            storage => #{
                                name => ?TK_AUTHORITY_APIKEYMGMT
                            }
                        }}
                }
        }},
        {tokens, #{
            jwt => #{
                authority_bindings => #{
                    ?TK_KEY_APIKEYMGMT => ?TK_AUTHORITY_APIKEYMGMT
                },
                keyset => #{
                    ?TK_KEY_APIKEYMGMT => #{
                        source => {pem_file, get_filename("keys/local/private.pem", C)}
                    }
                }
            }
        }},
        {storages, #{
            ?TK_AUTHORITY_APIKEYMGMT =>
                {machinegun, #{
                    machinery_backend => MachineryMode,
                    namespace => apikeymgmt,
                    automaton => #{
                        url => <<"http://machinegun:8022/v1/automaton">>,
                        event_handler => [scoper_woody_event_handler],
                        transport_opts => #{}
                    }
                }}
        }}
    ]),
    ServiceUrls = #{
        token_authenticator => mk_url(AuthenticatorPath),
        {token_authority, ?TK_AUTHORITY_APIKEYMGMT} => mk_url(AuthorityPath)
    },
    [{groupname, Name}, {service_urls, ServiceUrls} | C0 ++ C].

-spec end_per_group(group_name(), config()) -> _.
end_per_group(_GroupName, C) ->
    ok = stop_keeper(C),
    ok.

-spec init_per_testcase(atom(), config()) -> config().
init_per_testcase(Name, C) ->
    [{testcase, Name} | C].

-spec end_per_testcase(atom(), config()) -> ok.
end_per_testcase(_Name, _C) ->
    ok.

%%

-spec authenticate_invalid_token_type_fail(config()) -> _.
authenticate_invalid_token_type_fail(C) ->
    Token = <<"BLAH">>,
    ?assertThrow(#token_keeper_InvalidToken{}, call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, C)).

-spec authenticate_invalid_token_key_fail(config()) -> _.
authenticate_invalid_token_key_fail(C) ->
    Token = issue_dummy_token(C),
    ?assertThrow(#token_keeper_InvalidToken{}, call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, C)).

-spec authenticate_no_payload_claims_fail(config()) -> _.
authenticate_no_payload_claims_fail(C) ->
    JTI = unique_id(),
    Claims = get_base_claims(JTI),
    Token = issue_token(Claims, C),
    ?assertThrow(#token_keeper_AuthDataNotFound{}, call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, C)).

-spec authenticate_phony_api_key_token_ok(config()) -> _.
authenticate_phony_api_key_token_ok(C) ->
    JTI = unique_id(),
    SubjectID = unique_id(),
    Claims = get_phony_api_key_claims(JTI, SubjectID),
    Token = issue_token(Claims, C),
    #token_keeper_AuthData{
        id = undefined,
        token = Token,
        status = active,
        context = Context,
        metadata = #{?META_PARTY_ID := SubjectID},
        authority = ?TK_AUTHORITY_KEYCLOAK
    } = call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, C),
    _ = assert_context({api_key_token, #{jti => JTI, subject_id => SubjectID}}, Context).

-spec authenticate_user_session_token_ok(config()) -> _.
authenticate_user_session_token_ok(C) ->
    JTI = unique_id(),
    SubjectID = unique_id(),
    SubjectEmail = <<"test@test.test">>,
    Claims = get_user_session_token_claims(JTI, 0, SubjectID, SubjectEmail),
    Token = issue_token(Claims, C),
    #token_keeper_AuthData{
        id = undefined,
        token = Token,
        status = active,
        context = Context,
        metadata = #{
            ?META_USER_ID := SubjectID,
            ?META_USER_EMAIL := SubjectEmail,
            ?META_USER_REALM := <<"external">>
        },
        authority = ?TK_AUTHORITY_KEYCLOAK
    } = call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT(?USER_TOKEN_SOURCE), C),
    _ = assert_context(
        {user_session_token, #{jti => JTI, subject_id => SubjectID, subject_email => SubjectEmail}},
        Context
    ).

-spec authenticate_user_session_token_no_exp_fail(config()) -> _.
authenticate_user_session_token_no_exp_fail(C) ->
    JTI = unique_id(),
    SubjectID = unique_id(),
    SubjectEmail = <<"test@test.test">>,
    Claims = get_user_session_token_claims(JTI, 0, SubjectID, SubjectEmail),
    Token = issue_token(maps:remove(<<"exp">>, Claims), C),
    ?assertThrow(
        #token_keeper_AuthDataNotFound{},
        call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT(?USER_TOKEN_SOURCE), C)
    ).

-spec authenticate_user_session_token_w_exp_ok(config()) -> _.
authenticate_user_session_token_w_exp_ok(C) ->
    JTI = unique_id(),
    SubjectID = unique_id(),
    SubjectEmail = <<"test@test.test">>,
    Claims = get_user_session_token_claims(JTI, 42, SubjectID, SubjectEmail),
    Token = issue_token(Claims, C),
    #token_keeper_AuthData{
        context = Context
    } = call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT(?USER_TOKEN_SOURCE), C),
    _ = assert_context(
        {user_session_token, #{
            jti => JTI, subject_id => SubjectID, subject_email => SubjectEmail, exp => make_auth_expiration(42)
        }},
        Context
    ).

-spec authenticate_user_session_token_w_resource_access(config()) -> _.
authenticate_user_session_token_w_resource_access(C) ->
    JTI = unique_id(),
    SubjectID = unique_id(),
    SubjectEmail = <<"test@test.test">>,
    ResourceAccess = #{
        <<"api.2">> => #{
            <<"roles">> => [<<"do.2">>, <<"do.1">>]
        },
        <<"api.1">> => #{
            <<"roles">> => [<<"do.something">>]
        }
    },
    Claims = get_user_session_token_claims(JTI, 42, SubjectID, SubjectEmail, ResourceAccess),
    Token = issue_token(Claims, C),
    #token_keeper_AuthData{
        context = Context
    } = call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT(?USER_TOKEN_SOURCE), C),
    _ = assert_context(
        {user_session_token, #{
            jti => JTI,
            subject_id => SubjectID,
            subject_email => SubjectEmail,
            exp => make_auth_expiration(42),
            access => [
                {<<"api.1">>, [<<"do.something">>]},
                {<<"api.2">>, [<<"do.1">>, <<"do.2">>]}
            ]
        }},
        Context
    ).

-spec authenticate_user_session_token_no_payload_claims_fail(config()) -> _.
authenticate_user_session_token_no_payload_claims_fail(C) ->
    JTI = unique_id(),
    Claims = get_base_claims(JTI),
    Token = issue_token(Claims, C),
    ?assertThrow(
        #token_keeper_AuthDataNotFound{},
        call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT(?USER_TOKEN_SOURCE), C)
    ).

-spec authenticate_blacklisted_jti_fail(config()) -> _.
authenticate_blacklisted_jti_fail(C) ->
    JTI = <<"MYCOOLKEY">>,
    SubjectID = unique_id(),
    Claims = get_phony_api_key_claims(JTI, SubjectID),
    Token = issue_token_with(Claims, get_filename("keys/local/private.pem", C)),
    ?assertThrow(#token_keeper_AuthDataRevoked{}, call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, C)).

-spec authenticate_non_blacklisted_jti_ok(config()) -> _.
authenticate_non_blacklisted_jti_ok(C) ->
    JTI = <<"MYCOOLKEY">>,
    SubjectID = unique_id(),
    Claims = get_phony_api_key_claims(JTI, SubjectID),
    Token = issue_token_with(Claims, get_filename("keys/secondary/private.pem", C)),
    ?assertMatch(#token_keeper_AuthData{}, call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, C)).

-spec authenticate_blacklisted_user_fail(config()) -> _.
authenticate_blacklisted_user_fail(C) ->
    JTI = unique_id(),
    SubjectID = <<"PARTYID">>,
    Claims = get_phony_api_key_claims(JTI, SubjectID),
    Token = issue_token_with(Claims, get_filename("keys/local/private.pem", C)),
    ?assertThrow(#token_keeper_AuthDataNotFound{}, call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, C)).

-spec authenticate_ephemeral_claim_token_ok(config()) -> _.
authenticate_ephemeral_claim_token_ok(C) ->
    JTI = unique_id(),
    ContextFragment = create_encoded_bouncer_context(JTI),
    Metadata = #{<<"my metadata">> => <<"is here">>},
    AuthorityID = ?TK_AUTHORITY_CAPI,
    #token_keeper_AuthData{
        id = undefined,
        token = Token,
        status = active,
        context = Context,
        metadata = Metadata
    } = call_create_ephemeral(AuthorityID, ContextFragment, Metadata, C),
    #token_keeper_AuthData{
        id = undefined,
        token = Token,
        status = active,
        context = Context,
        metadata = Metadata,
        authority = AuthorityID
    } = call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, C),
    _ = assert_context({claim_token, #{jti => JTI}}, Context).

-spec issue_ephemeral_token_ok(config()) -> _.
issue_ephemeral_token_ok(C) ->
    JTI = unique_id(),
    ContextFragment = create_encoded_bouncer_context(JTI),
    Metadata = #{<<"my metadata">> => <<"is here">>},
    AuthorityID = ?TK_AUTHORITY_CAPI,
    #token_keeper_AuthData{
        id = undefined,
        status = active,
        metadata = Metadata
    } = call_create_ephemeral(AuthorityID, ContextFragment, Metadata, C).

-spec authenticate_offline_token_not_found_fail(config()) -> _.
authenticate_offline_token_not_found_fail(C) ->
    JTI = unique_id(),
    Claims = get_base_claims(JTI),
    Token = issue_token(Claims, C),
    ?assertThrow(#token_keeper_AuthDataNotFound{}, call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, C)).

-spec authenticate_offline_token_revoked_fail(config()) -> _.
authenticate_offline_token_revoked_fail(C) ->
    JTI = unique_id(),
    ContextFragment = create_encoded_bouncer_context(JTI),
    Metadata = #{<<"my metadata">> => <<"is here">>},
    AuthorityID = ?TK_AUTHORITY_APIKEYMGMT,
    #token_keeper_AuthData{
        id = JTI,
        token = Token,
        status = active
    } = call_create(AuthorityID, JTI, ContextFragment, Metadata, C),
    ok = call_revoke(AuthorityID, JTI, C),
    ?assertThrow(#token_keeper_AuthDataRevoked{}, call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, C)).

-spec authenticate_offline_token_ok(config()) -> _.
authenticate_offline_token_ok(C) ->
    JTI = unique_id(),
    ContextFragment = create_encoded_bouncer_context(JTI),
    Metadata = #{<<"my metadata">> => <<"is here">>},
    AuthorityID = ?TK_AUTHORITY_APIKEYMGMT,
    #token_keeper_AuthData{
        id = JTI,
        token = Token,
        status = active,
        context = Context,
        metadata = Metadata
    } = call_create(AuthorityID, JTI, ContextFragment, Metadata, C),
    #token_keeper_AuthData{
        id = JTI,
        token = Token,
        status = active,
        context = Context,
        metadata = Metadata,
        authority = AuthorityID
    } = call_authenticate(Token, ?TOKEN_SOURCE_CONTEXT, C),
    _ = assert_context({claim_token, #{jti => JTI}}, Context).

-spec issue_offline_token_ok(config()) -> _.
issue_offline_token_ok(C) ->
    JTI = unique_id(),
    ContextFragment = create_encoded_bouncer_context(JTI),
    Metadata = #{<<"my metadata">> => <<"is here">>},
    AuthorityID = ?TK_AUTHORITY_APIKEYMGMT,
    #token_keeper_AuthData{
        id = JTI,
        status = active
    } = call_create(AuthorityID, JTI, ContextFragment, Metadata, C).

-spec issue_duplicate_offline_token_fail(config()) -> _.
issue_duplicate_offline_token_fail(C) ->
    JTI = unique_id(),
    ContextFragment = create_encoded_bouncer_context(JTI),
    Metadata = #{},
    AuthorityID = ?TK_AUTHORITY_APIKEYMGMT,
    #token_keeper_AuthData{
        id = JTI,
        status = active
    } = call_create(AuthorityID, JTI, ContextFragment, Metadata, C),
    ?assertThrow(
        #token_keeper_AuthDataAlreadyExists{},
        call_create(AuthorityID, JTI, ContextFragment, Metadata, C)
    ).

-spec get_authdata_by_id_ok(config()) -> _.
get_authdata_by_id_ok(C) ->
    JTI = unique_id(),
    ContextFragment = create_encoded_bouncer_context(JTI),
    Metadata = #{<<"my metadata">> => <<"is here">>},
    AuthorityID = ?TK_AUTHORITY_APIKEYMGMT,
    #token_keeper_AuthData{
        id = JTI,
        token = _,
        status = active,
        context = Context,
        metadata = Metadata
    } = call_create(AuthorityID, JTI, ContextFragment, Metadata, C),
    #token_keeper_AuthData{
        id = JTI,
        token = undefined,
        status = active,
        context = Context,
        metadata = Metadata
    } = call_get(AuthorityID, JTI, C).

-spec get_authdata_by_id_not_found_fail(config()) -> _.
get_authdata_by_id_not_found_fail(C) ->
    JTI = unique_id(),
    AuthorityID = ?TK_AUTHORITY_APIKEYMGMT,
    ?assertThrow(#token_keeper_AuthDataNotFound{}, call_get(AuthorityID, JTI, C)).

-spec revoke_authdata_by_id_ok(config()) -> _.
revoke_authdata_by_id_ok(C) ->
    JTI = unique_id(),
    ContextFragment = create_encoded_bouncer_context(JTI),
    Metadata = #{},
    AuthorityID = ?TK_AUTHORITY_APIKEYMGMT,
    #token_keeper_AuthData{
        id = JTI,
        status = active
    } = call_create(AuthorityID, JTI, ContextFragment, Metadata, C),
    ok = call_revoke(AuthorityID, JTI, C),
    #token_keeper_AuthData{
        id = JTI,
        status = revoked
    } = RevokedAuthData = call_get(AuthorityID, JTI, C),
    ok = call_revoke(AuthorityID, JTI, C),
    ?assertEqual(RevokedAuthData, call_get(AuthorityID, JTI, C)).

-spec revoke_authdata_by_id_not_found_fail(config()) -> _.
revoke_authdata_by_id_not_found_fail(C) ->
    JTI = unique_id(),
    AuthorityID = ?TK_AUTHORITY_APIKEYMGMT,
    ?assertThrow(#token_keeper_AuthDataNotFound{}, call_revoke(AuthorityID, JTI, C)).

%%

make_auth_expiration(Timestamp) ->
    genlib_rfc3339:format(Timestamp, second).

get_base_claims(JTI) ->
    get_base_claims(JTI, 0).

get_base_claims(JTI, Exp) ->
    #{
        <<"jti">> => JTI,
        <<"exp">> => Exp
    }.

get_phony_api_key_claims(JTI, SubjectID) ->
    maps:merge(#{<<"sub">> => SubjectID}, get_base_claims(JTI)).

get_user_session_token_claims(JTI, Exp, SubjectID, SubjectEmail) ->
    get_user_session_token_claims(JTI, Exp, SubjectID, SubjectEmail, undefined).

get_user_session_token_claims(JTI, Exp, SubjectID, SubjectEmail, ResourceAccess) ->
    maps:merge(
        genlib_map:compact(#{
            <<"sub">> => SubjectID,
            <<"email">> => SubjectEmail,
            <<"resource_access">> => ResourceAccess
        }),
        get_base_claims(JTI, Exp)
    ).

create_bouncer_context(JTI) ->
    bouncer_context_helpers:add_auth(
        #{
            method => <<"ClaimToken">>,
            token => #{id => JTI}
        },
        bouncer_context_helpers:empty()
    ).

create_encoded_bouncer_context(JTI) ->
    Fragment = create_bouncer_context(JTI),
    #ctx_ContextFragment{
        type = v1_thrift_binary,
        content = encode_context_fragment_content(Fragment)
    }.

%%

mk_client(C) ->
    WoodyCtx = woody_context:new(genlib:to_binary(?CONFIG(testcase, C))),
    ServiceURLs = ?CONFIG(service_urls, C),
    {WoodyCtx, ServiceURLs}.

call_authenticate(Token, TokenSourceContext, C) ->
    call_token_authenticator('Authenticate', {Token, TokenSourceContext}, C).

call_create_ephemeral(AuthorityID, Context, Metadata, C) ->
    call_token_ephemeral_authority(AuthorityID, 'Create', {Context, Metadata}, C).

call_create(AuthorityID, ID, Context, Metadata, C) ->
    call_token_authority(AuthorityID, 'Create', {ID, Context, Metadata}, C).

call_get(AuthorityID, ID, C) ->
    call_token_authority(AuthorityID, 'Get', {ID}, C).

call_revoke(AuthorityID, ID, C) ->
    call_token_authority(AuthorityID, 'Revoke', {ID}, C).

call_token_authenticator(Operation, Args, C) ->
    call(token_authenticator, Operation, Args, mk_client(C)).

call_token_authority(ID, Operation, Args, C) ->
    call({token_authority, ID}, Operation, Args, mk_client(C)).

call_token_ephemeral_authority(ID, Operation, Args, C) ->
    call({token_ephemeral_authority, ID}, Operation, Args, mk_client(C)).

call(ServiceName, Fn, Args, {WoodyCtx, ServiceURLs}) ->
    Service = get_service_spec(ServiceName),
    Opts = #{
        url => maps:get(ServiceName, ServiceURLs),
        event_handler => scoper_woody_event_handler
    },
    case woody_client:call({Service, Fn, Args}, Opts, WoodyCtx) of
        {ok, Response} ->
            Response;
        {exception, Exception} ->
            throw(Exception)
    end.

get_service_spec(token_authenticator) ->
    {tk_token_keeper_thrift, 'TokenAuthenticator'};
get_service_spec({token_authority, _}) ->
    {tk_token_keeper_thrift, 'TokenAuthority'};
get_service_spec({token_ephemeral_authority, _}) ->
    {tk_token_keeper_thrift, 'EphemeralTokenAuthority'}.

%%

-define(CTX_ENTITY(ID), #base_Entity{id = ID}).

encode_context_fragment_content(ContextFragment) ->
    Type = {struct, struct, {bouncer_ctx_v1_thrift, 'ContextFragment'}},
    Codec = thrift_strict_binary_codec:new(),
    case thrift_strict_binary_codec:write(Codec, Type, ContextFragment) of
        {ok, Codec1} ->
            thrift_strict_binary_codec:close(Codec1)
    end.

decode_bouncer_fragment(#ctx_ContextFragment{type = v1_thrift_binary, content = Content}) ->
    Type = {struct, struct, {bouncer_ctx_v1_thrift, 'ContextFragment'}},
    Codec = thrift_strict_binary_codec:new(Content),
    {ok, Fragment, _} = thrift_strict_binary_codec:read(Codec, Type),
    Fragment.

assert_context(TokenInfo, EncodedContextFragment) ->
    #ctx_v1_ContextFragment{auth = Auth, user = User} = decode_bouncer_fragment(EncodedContextFragment),
    _ = assert_auth(TokenInfo, Auth),
    _ = assert_user(TokenInfo, User).

assert_auth({claim_token, #{jti := JTI}}, Auth) ->
    ?assertEqual(<<"ClaimToken">>, Auth#ctx_v1_Auth.method),
    ?assertMatch(#ctx_v1_Token{id = JTI}, Auth#ctx_v1_Auth.token);
assert_auth({api_key_token, #{jti := JTI, subject_id := SubjectID}}, Auth) ->
    ?assertEqual(<<"ApiKeyToken">>, Auth#ctx_v1_Auth.method),
    ?assertMatch(#ctx_v1_Token{id = JTI}, Auth#ctx_v1_Auth.token),
    ?assertMatch([#ctx_v1_AuthScope{party = ?CTX_ENTITY(SubjectID)}], Auth#ctx_v1_Auth.scope);
assert_auth({user_session_token, #{jti := JTI} = TokenInfo}, Auth) ->
    ?assertEqual(<<"SessionToken">>, Auth#ctx_v1_Auth.method),
    Exp = maps:get(exp, TokenInfo, undefined),
    Access =
        case maps:get(access, TokenInfo, undefined) of
            undefined ->
                undefined;
            AccessList ->
                [
                    #ctx_v1_ResourceAccess{
                        id = ID,
                        roles = Roles
                    }
                 || {ID, Roles} <- AccessList
                ]
        end,
    ?assertMatch(#ctx_v1_Token{id = JTI, access = Access}, Auth#ctx_v1_Auth.token),
    ?assertEqual(Exp, Auth#ctx_v1_Auth.expiration).

assert_user({claim_token, _}, undefined) ->
    ok;
assert_user({api_key_token, _}, undefined) ->
    ok;
assert_user({user_session_token, #{subject_id := SubjectID, subject_email := SubjectEmail}}, User) ->
    ?assertEqual(SubjectID, User#ctx_v1_User.id),
    ?assertEqual(SubjectEmail, User#ctx_v1_User.email),
    ?assertEqual(?CTX_ENTITY(<<"external">>), User#ctx_v1_User.realm).

%%

-include_lib("jose/include/jose_jwk.hrl").

issue_token(Claims, Config) ->
    issue_token_with(Claims, get_filename("keys/local/private.pem", Config)).

issue_token_with(Claims, PemFile) ->
    JWK = jose_jwk:from_pem_file(PemFile),
    JWKPublic = jose_jwk:to_public(JWK),
    {_Module, PublicKey} = JWKPublic#jose_jwk.kty,
    {_PemEntry, Data, _} = public_key:pem_entry_encode('SubjectPublicKeyInfo', PublicKey),
    KID = jose_base64url:encode(crypto:hash(sha256, Data)),
    JWT = jose_jwt:sign(JWK, #{<<"alg">> => <<"RS256">>, <<"kid">> => KID}, Claims),
    {_Modules, Token} = jose_jws:compact(JWT),
    Token.

issue_dummy_token(Config) ->
    Claims = #{
        <<"jti">> => unique_id(),
        <<"sub">> => <<"TEST">>,
        <<"exp">> => 0
    },
    BadPemFile = get_filename("keys/local/dummy.pem", Config),
    BadJWK = jose_jwk:from_pem_file(BadPemFile),
    GoodPemFile = get_filename("keys/local/private.pem", Config),
    GoodJWK = jose_jwk:from_pem_file(GoodPemFile),
    JWKPublic = jose_jwk:to_public(GoodJWK),
    {_Module, PublicKey} = JWKPublic#jose_jwk.kty,
    {_PemEntry, Data, _} = public_key:pem_entry_encode('SubjectPublicKeyInfo', PublicKey),
    KID = jose_base64url:encode(crypto:hash(sha256, Data)),
    JWT = jose_jwt:sign(BadJWK, #{<<"alg">> => <<"RS256">>, <<"kid">> => KID}, Claims),
    {_Modules, Token} = jose_jws:compact(JWT),
    Token.

%%

get_filename(Key, Config) ->
    filename:join(?config(data_dir, Config), Key).

unique_id() ->
    <<ID:64>> = snowflake:new(),
    genlib_format:format_int_base(ID, 62).

%%

start_keeper(Env) ->
    Port = 8022,
    Apps = genlib_app:start_application_with(
        token_keeper,
        [
            {port, Port},
            {machinegun, #{
                processor => #{
                    path => <<"/v2/stateproc">>
                }
            }}
        ] ++ Env
    ),
    [{keeper_apps, Apps}].

stop_keeper(C) ->
    genlib_app:stop_unload_applications(?CONFIG(keeper_apps, C)).

mk_url(Path) ->
    mk_url("127.0.0.1", 8022, Path).

mk_url(IP, Port, Path) ->
    iolist_to_binary(["http://", IP, ":", genlib:to_binary(Port), Path]).

extract_method_detect_token() ->
    {extract_context, #{
        methods => [
            {detect_token, #{
                phony_api_key_opts => #{
                    metadata_mappings => #{
                        party_id => ?META_PARTY_ID
                    }
                },
                user_session_token_opts => #{
                    user_realm => <<"external">>,
                    metadata_mappings => #{
                        user_id => ?META_USER_ID,
                        user_email => ?META_USER_EMAIL,
                        user_realm => ?META_USER_REALM
                    }
                },
                user_session_token_origins => [?USER_TOKEN_SOURCE]
            }}
        ]
    }}.
