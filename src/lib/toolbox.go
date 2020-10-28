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

package lib

import (
	"Yearning-go/src/model"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
    "database/sql"
	"github.com/cookieY/yee"
	_ "github.com/go-sql-driver/mysql"
	"gopkg.in/ldap.v3"
	"log"
	"math"
	"math/rand"
	"strconv"
	"time"
    "regexp"
    "errors"
    "context"
)

func ResearchDel(s []string, p string) []string {
	for in := 0; in < len(s); in++ {
		if s[in] == p {
			s = append(s[:in], s[in+1:]...)
			in--
		}
	}
	return s
}

func Paging(page interface{}, total int) (start int, end int) {
	var i int
	switch v := page.(type) {
	case string:
		i, _ = strconv.Atoi(v)
	case int:
		i = v
	}
	start = i*total - total
	end = total
	return
}

func LdapConnenct(c yee.Context, l *model.Ldap, user string, pass string, isTest bool) (map[string]string, bool) {

	var s string
	ld, err := ldap.Dial("tcp", l.Url)

    result := make(map[string]string)
	if l.Ldaps {
		if err := ld.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
			log.Println(err.Error())
		}
	}

	if err != nil {
		c.Logger().Error(err.Error())
		return result, false
	}
	defer ld.Close()

	if ld != nil {
		if err := ld.Bind(l.User, l.Password); err != nil {
			return result, false
		}
		if isTest {
			return result, true
		}

	}

	if l.Type == 1 {
		s = fmt.Sprintf("(sAMAccountName=%s)", user)
	} else if l.Type == 2 {
		s = fmt.Sprintf("(uid=%s)", user)
	} else {
		s = fmt.Sprintf("(cn=%s)", user)
	}

    attributes := []string{"dn"}
    if l.Name != "" {
        attributes = append(attributes, l.Name)
    }
    if l.Email != "" {
        attributes = append(attributes, l.Email)
    }
    if l.Department != "" {
        attributes = append(attributes, l.Department)
    }

	searchRequest := ldap.NewSearchRequest(
		l.Sc,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectClass=organizationalPerson)%s%s)", s, l.Filter),
        attributes,
		nil,
	)

	sr, err := ld.Search(searchRequest)

	if err != nil {
		log.Println(err.Error())
		return result, false
	}

	if len(sr.Entries) != 1 {
		log.Println("User does not exist or too many entries returned")
		return result, false
	}

	userdn := sr.Entries[0].DN

	if err := ld.Bind(userdn, pass); err != nil {
		c.Logger().Error(err.Error())
		return result, false
	}
    entry := sr.Entries[0]
    if l.Name != "" {
        result["name"] = entry.GetAttributeValue(l.Name)
    }
    if l.Department != "" {
        result["department"] = entry.GetAttributeValue(l.Department)
    }
    if l.Email != "" {
        result["email"] = entry.GetAttributeValue(l.Email)
    }
	return result, true
}

func Axis() []string {
	var s []string
	currentTime := time.Now()
	for a := 0; a < 7; a++ {
		oldTime := currentTime.AddDate(0, 0, -a)
		s = append(s, oldTime.Format("2006-01-02"))
	}
	return s
}

func GenWorkid() string {
	rand.Seed(time.Now().UnixNano())
	a := rand.Intn(1000)
	c := strconv.Itoa(a)
	now := time.Now()
	return now.Format("20060102150405") + c
}

func Intersect(o, n []string) []string {
	m := make(map[string]int)
	var arr []string
	for _, v := range o {
		m[v]++
	}
	for _, v := range n {
		m[v]++
		if m[v] > 1 {
			arr = append(arr, v)
		}
	}
	return arr
}

func NonIntersect(o, n []string) []string {
	m := make(map[string]int)
	var arr []string
	for _, v := range o {
		m[v]++
	}
	for _, v := range n {
		m[v]++
		if m[v] == 1 {
			arr = append(arr, v)
		}
	}
	return arr
}

func Time2StrDiff(delay string) time.Duration {
	if delay != "none" {
		now := time.Now()
		dt, _ := time.ParseInLocation("2006-01-02 15:04 ", delay, time.Local)
		after := dt.Sub(now)
		if after+1 > 0 {
			return after
		}
	}
	return 0
}

func TimeDifference(t string) bool {
	dt, _ := time.ParseInLocation("2006-01-02 15:04 ", t, time.Local)
	f := dt.Sub(time.Now())
	if math.Abs(f.Minutes()) > float64(model.GloOther.ExQueryTime) && float64(model.GloOther.ExQueryTime) > 0 {
		return true
	}
	return false
}

type querydata struct {
	Field []map[string]string
	Data  []map[string]interface{}
}

func SetExQueryTime(conn *sql.Conn, ctx context.Context, exQueryTime int) (error) {
    if exQueryTime == 0 {
        return nil
    }
    rows, err := conn.QueryContext(ctx, "SHOW VARIABLES LIKE 'max_statement_time'")
    if err != nil {
        return err
    }

    exQueryTime = exQueryTime * 1000
    hasResult := rows.Next()
    rows.Close()
    if hasResult {
        _, err := conn.ExecContext(ctx, fmt.Sprintf("SET max_statement_time = %d", exQueryTime))
        if err != nil {
            return err
        }
        return nil
    }
    _, err = conn.ExecContext(ctx, fmt.Sprintf("SET max_execution_time = %d", exQueryTime))
    if err != nil {
        return err
    }
    return nil
}

func checkLimitCount(sql string, limitCount int) (error) {
    if limitCount == 0 {
        return nil
    }

    // 不限制是否超过全局的配置
    // globalLimit, err := strconv.Atoi(model.GloOther.Limit)
    // if limitCount > globalLimit && globalLimit > 0 {
    //     limitCount = globalLimit
    // }

    var limit int
    var re = regexp.MustCompile(`(?i)limit\s+(\d+)[\s;]*$`)
    results := re.FindStringSubmatch(sql)
    if len(results) >= 2 {
        limit, _ = strconv.Atoi(results[1])
    }
    if limitCount > 0 && limit > limitCount {
        return errors.New(fmt.Sprintf("您每次最多可以查询 %d 条记录", limitCount))
    }
    return nil
}

func QueryMethod(source *model.CoreDataSource, req *model.Queryresults, wordList []string, queryParams model.QueryParams) (querydata, error) {

	var qd querydata

    err := checkLimitCount(req.Sql, queryParams.LimitCount)
    if err != nil {
        return qd, err
    }

    var ctx context.Context
    ctx = context.Background()
    var params string
    if len(source.Params) > 2 {
        params = source.Params
    }
	ps := Decrypt(source.Password)
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&%s", source.Username, ps, source.IP, source.Port, req.Basename, params))
	if err != nil {
		return qd, err
	}
	defer db.Close()
    // db.Close()

    conn, err := db.Conn(ctx)
    if err != nil {
        return qd, err
    }
    defer conn.Close()
    err = conn.PingContext(ctx)
    if err != nil {
        return qd, err
    }

    SetExQueryTime(conn, ctx, queryParams.ExQueryTime)

	rows, err := conn.QueryContext(ctx, req.Sql)
	if err != nil {
		return qd, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return qd, err
	}

    nodupcols := removeDuplicateElement(cols)
	for rows.Next() {
		results := make(map[string]interface{})

		values := make([]interface{}, len(cols))
		for i := range values {
			values[i] = new(interface{})
		}

		err = rows.Scan(values...)
		if err != nil {
			return qd, err
		}

		for i, column := range nodupcols {
			results[column] = *(values[i].(*interface{}))
		}

		for idx := range results {
			switch r := results[idx].(type) {
			case []uint8:
				if len(r) > 10000 {
					results[idx] = "blob字段无法显示"
				} else {
					if hex.EncodeToString(r) == "01" {
						results[idx] = "true"
					} else if hex.EncodeToString(r) == "00" {
						results[idx] = "false"
					} else {
						results[idx] = string(r)
					}
				}
			}
		}
		if len(wordList) > 0 {
			for ok := range results {
				for _, exclude := range wordList {
					if ok == exclude {
						results[ok] = "****脱敏字段"
					}
				}
			}
		}

		qd.Data = append(qd.Data, results)
	}

	for _, cv := range nodupcols {
		qd.Field = append(qd.Field, map[string]string{"title": cv, "key": cv, "width": "200"})
	}
	qd.Field[0]["fixed"] = "left"

	return qd, nil
}

func removeDuplicateElement(addrs []string) []string {
	result := make([]string, 0, len(addrs))
	temp := map[string]struct{}{}
	idx := 0
	for _, item := range addrs {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		} else {
			idx++
			item += fmt.Sprintf("(%v)", idx)
			result = append(result, item)
		}
	}
	return result
}

func JsonStringify(i interface{}) []byte {
	o, _ := json.Marshal(i)
	return o
}



func removeDuplicateElementForRule(addrs []string) []string {
	result := make([]string, 0, len(addrs))
	temp := map[string]struct{}{}
	for _, item := range addrs {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

func MulitUserRuleMarge(group []string) model.PermissionList {
	var u model.PermissionList
	for _, i := range group {
		var k model.CoreRoleGroup
		model.DB().Where("name =?", i).First(&k)
		var m1 model.PermissionList
		_ = json.Unmarshal(k.Permissions, &m1)
		u.DDLSource = append(u.DDLSource, m1.DDLSource...)
		u.DMLSource = append(u.DMLSource, m1.DMLSource...)
		u.QuerySource = append(u.QuerySource, m1.QuerySource...)
		u.Auditor = append(u.Auditor, m1.Auditor...)
	}
	u.DDLSource = removeDuplicateElementForRule(u.DDLSource)
	u.DMLSource = removeDuplicateElementForRule(u.DMLSource)
	u.Auditor = removeDuplicateElementForRule(u.Auditor)
	u.QuerySource = removeDuplicateElementForRule(u.QuerySource)

	return u
}

func GetCorrectQueryParams(maxParams model.QueryParams, params model.QueryParams) (model.QueryParams) {
    if params.LimitCount > maxParams.LimitCount {
        params.LimitCount = 0
    }
    if params.ExQueryTime > maxParams.ExQueryTime {
        params.ExQueryTime = 0
    }
    return params
}

func GetUserQueryParams(user string, source string, dataSource model.CoreDataSource) (model.QueryParams, error) {
    var ret model.QueryParams
    var params model.QueryParams
    var maxParams model.QueryParams
    var user_row model.CoreAccount
    var group_row model.CoreGrained
    var groups []string
    var queryParams []model.QueryParams


    // 1. 获取全局配置
    maxParams.LimitCount, _ = strconv.Atoi(model.GloOther.Limit)
    maxParams.ExQueryTime = model.GloOther.ExQueryTime

    // 2. 如果数据库配置了，则使用数据库的配置
    if dataSource.LimitCount > 0 {
        maxParams.LimitCount = dataSource.LimitCount
    }
    if dataSource.ExQueryTime > 0 {
        maxParams.ExQueryTime = dataSource.ExQueryTime
    }

    // 3. 获取用户的参数配置
    //    如果用户配置了参数，且未超过最大的配置，则使用用户的配置
    //    如果用户配置的参数超过最大的配置，则使用最大的配置
    model.DB().Where("username = ?", user).Take(&user_row)
    _ = json.Unmarshal(user_row.QueryParams, &params)

    ret = GetCorrectQueryParams(maxParams, params)
    if ret.LimitCount > 0 && ret.ExQueryTime > 0 {
        return ret, nil
    }

    // 4 获取用户所属的权限组
    params.LimitCount = 0
    params.ExQueryTime = 0
    model.DB().Where("username = ?", user).Take(&group_row)
    _ = json.Unmarshal(group_row.Group, &groups)

    if len(groups) > 0 {
        // 4.1 获取用户权限组对应的参数配置，如果权限组配置了，则使用权限组配置
        model.DB().Model(&model.CoreRoleGroup{}).Select("query_params").Limit(1000).Where("name in (?)", groups).Where("JSON_SEARCH(permissions, 'one', ?, 1, '$.query_source') is not null", source).Scan(&queryParams)

        // 选择最大的那个 LimitCount 以及 ExQueryTime
        for _, i := range queryParams {
            if params.LimitCount < i.LimitCount {
                params.LimitCount = i.LimitCount
            }
            if params.ExQueryTime < i.ExQueryTime {
                params.ExQueryTime = i.ExQueryTime
            }
        }

        params = GetCorrectQueryParams(maxParams, params)
    }
    // 权限组为空，则使用最大值
    if params.LimitCount == 0  {
        params.LimitCount = maxParams.LimitCount
    }
    if params.ExQueryTime == 0 {
        params.ExQueryTime = maxParams.ExQueryTime
    }

    // 用户为空，则使用权限组
    if ret.LimitCount == 0 {
        ret.LimitCount = params.LimitCount
    }
    if ret.ExQueryTime == 0 {
        ret.ExQueryTime = params.ExQueryTime
    }

    return ret, nil
}
