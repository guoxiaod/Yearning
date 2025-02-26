// Copyright 2019 HenryYee.
//
// Licensed under the AGPL, Version 3.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.gnu.org/licenses/agpl-3.0.en.html
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// See the License for the specific language governing permissions and
// limitations under the License.

package model

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"log"
	"os"
	"time"
)

var db *gorm.DB

type Other struct {
	Limit            string   `json:"limit"`
	IDC              []string `json:"idc"`
	Multi            bool     `json:"multi"`
	Query            bool     `json:"query"`
	ExcludeDbList    []string `json:"exclude_db_list"`
	InsulateWordList []string `json:"insulate_word_list"`
	Register         bool     `json:"register"`
	Export           bool     `json:"export"`
	PerOrder         int      `json:"per_order"`
	ExQueryTime      int      `json:"ex_query_time"`
	QueryTimeout     int      `json:"query_timeout"`
}

type Message struct {
	WebHook  string `json:"web_hook"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	ToUser   string `json:"to_user"`
	Mail     bool   `json:"mail"`
	Ding     bool   `json:"ding"`
	Ssl      bool   `json:"ssl"`
	PushType bool   `json:"push_type"`
}

type Ldap struct {
	Url        string `json:"url"`
	User       string `json:"user"`
	Password   string `json:"password"`
	Type       int    `json:"type"`
	Sc         string `json:"sc"`
	Ldaps      bool   `json:"ldaps"`
    Filter     string `json:"filter"`
    Name       string `json:"name"`
    Department string `json:"department"`
    Email      string `json:"email"`
}

type QueryParams struct {
    LimitCount  int     `json:"limit_count"`
    ExQueryTime int     `json:"ex_query_time"`
}

type PermissionList struct {
	DDLSource   []string `json:"ddl_source"`
	DMLSource   []string `json:"dml_source"`
	Auditor     []string `json:"auditor"`
	QuerySource []string `json:"query_source"`
}

type MargeList struct {
	DDL         int      `json:"ddl"`
	DDLSource   []string `json:"ddl_source"`
	DML         int      `json:"dml"`
	DMLSource   []string `json:"dml_source"`
	User        int      `json:"user"`
	Base        int      `json:"base"`
	Auditor     []string `json:"auditor"`
	Query       int      `json:"query"`
	QuerySource []string `json:"query_source"`
}

type Permission struct {
	Permissions PermissionList `json:"permissions"`
}

type Queryresults struct {
	Sql      string
	Basename string
	Source   string
    Changed  bool
}

func DbInit(c string) {
	_, err := toml.DecodeFile(c, &C)
	if err != nil {
		log.Println(err.Error())
	}
	Grpc = C.General.GrpcAddr
	JWT = C.General.SecretKey
	newDb, err := gorm.Open("mysql", fmt.Sprintf("%s:%s@(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local", C.Mysql.User, C.Mysql.Password, C.Mysql.Host, C.Mysql.Port, C.Mysql.Db))
	if err != nil {
		newDb, err = gorm.Open("mysql", fmt.Sprintf("%s:%s@(%s)/%s?charset=utf8mb4&parseTime=True&loc=Local", os.Getenv("MYSQL_USER"), os.Getenv("MYSQL_PASSWORD"), os.Getenv("MYSQL_ADDR"), os.Getenv("MYSQL_DB")))
		if err != nil {
			fmt.Println("mysql连接失败! 亲 数据库建了没？ 配置填对了没？")
			os.Exit(1)
		}
	}
	db = newDb
	sqlDb := db.DB()
	sqlDb.SetConnMaxLifetime(time.Minute * 10)
	sqlDb.SetMaxOpenConns(50)
	sqlDb.SetMaxIdleConns(15)
}

func DB() *gorm.DB {
	return db.New()
}

func (D *DbInfo) CreateTable() {
	DB().CreateTable(&CoreQueryOrder{})
	//DB().AutoMigrate(&Account{})
	//DB().Model(&GlobalConfiguration{}).ModifyColumn("inception", "json")

	//DB().AutoMigrate(&CoreGlobalConfiguration{})
	//DB().AutoMigrate(&CoreSqlOrder{})
}
