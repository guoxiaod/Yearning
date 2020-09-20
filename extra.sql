alter table core_data_sources 
    add params varchar(500) not null default '',
    add limit_count int not null default 0,
    add ex_query_time int not null default 0;

alter table core_accounts
    add query_params json default null;

alter table core_role_groups
    add query_params json default null;
