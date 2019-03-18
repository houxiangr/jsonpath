package jsonpath

import (
	"errors"
	"fmt"
	"git.xiaojukeji.com/ihap/ihap-auth-sdk/conf"
	"go/token"
	"go/types"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

//获取nil object错误模板
var ErrGetFromNullObj = errors.New("get attribute from null object")

//用作标记递归列过滤和脱敏的全局变量
var curr = 0

//脱敏模板函数类型
type HandlerDesensitization func(jsonMap map[string]interface{}, key string) error

//保存脱敏函数列表
//在Init函数中初始化这个map
var DesensitizationFuncs = make(map[string]HandlerDesensitization)

//最大整数
const INT_MAX = int(^uint(0) >> 1)

//path 输入的jsonpath字符串
//steps 解析jsonpath后,操作json的具体步骤
type Compiled struct {
	path  string
	steps []step
}

//操作的单个步骤
//op 具体操作符(必须，有:root,key,idx,range,scan)
//key 如果步骤中有键值则保存键值
//args 参数列表，用作保存参数，主要用于idx和range操作
type step struct {
	op   string
	key  string
	args interface{}
}

//具体脱敏方式结构体
//displayChar 脱敏字符
//start 脱敏开始位置
//size 脱敏结束位置
type desensitization struct {
	displayChar string
	start       int
	size        int
}

func init() {
	//初始化当前支持的脱敏函数map
	DesensitizationFuncs[conf.CarNumberDesensitization] = carNumberDesensitization
	DesensitizationFuncs[conf.PhoneDesensitization] = phoneDesensitization
	DesensitizationFuncs[conf.IdCardNumberDesensitization] = idCardNumberDesensitization
	DesensitizationFuncs[conf.NameDesensitization] = nameDesensitization
}

//向外暴露通过jsonpath的查询接口
//obj json Unmarshal解析成的字节数组
//jpath jsonpath字符串
func JsonPathLookUp(obj interface{}, jpath string) (interface{}, error) {
	c, err := Compile(jpath)
	if err != nil {
		return nil, err
	}
	return c.Lookup(obj)
}

//向外暴露通过jsonpath的列过滤接口
func JsonPathLookUpAndDel(obj interface{}, jpath string) (interface{}, error) {
	c, err := Compile(jpath)
	if err != nil {
		return nil, err
	}
	return c.LookupAndOperate(obj, conf.DataFieldControl, "")
}

//向外暴露通过jsonpath的数据脱敏接口
func JsonPathLookUpAndDesensitization(obj interface{}, jpath string, opertFunc string) (interface{}, error) {
	c, err := Compile(jpath)
	if err != nil {
		return nil, err
	}
	return c.LookupAndOperate(obj, conf.DataDesensitizationControl, opertFunc)
}

func MustCompile(jpath string) *Compiled {
	c, err := Compile(jpath)
	if err != nil {
		panic(err)
	}
	return c
}

//解析jsonpath，返回Compiled结构
func Compile(jpath string) (*Compiled, error) {
	//tokens 分词后的结果数组
	tokens, err := tokenize(jpath)
	if err != nil {
		return nil, err
	}
	if tokens[0] != "@" && tokens[0] != "$" {
		return nil, fmt.Errorf("$ or @ should in front of path")
	}
	tokens = tokens[1:]
	//保存steps的操作数组
	res := Compiled{
		path:  jpath,
		steps: []step{},
	}
	tokenLen := len(tokens)
	for i := 0; i < tokenLen; i++ {
		//如果是递归操作直接获取下一个token做key保存进step
		if tokens[i] == "*" {
			i++
			op, key, args, err := parse_token(tokens[i])
			if err != nil {
				return nil, err
			}
			// 如果后面出现参数范围限制，则添加相应的args
			if op == "range" || op == "idx" {
				res.steps = append(res.steps, step{"scan", key, args})
			} else {
				res.steps = append(res.steps, step{"scan", key, nil})
			}
		} else {
			op, key, args, err := parse_token(tokens[i])
			if err != nil {
				return nil, err
			}
			res.steps = append(res.steps, step{op, key, args})
		}
	}
	return &res, nil
}

//query,传入的jsonpath字符串
//将jsonpath进行分词，返回分词后的结果,
// 过滤：'[',']','.'操作符并解析成相应的操作
func tokenize(query string) ([]string, error) {
	tokens := []string{}
	//	token_start := false
	//	token_end := false
	//临时保存当前字符串的变量
	token := ""

	// fmt.Println("-------------------------------------------------- start")
	for idx, x := range query {
		//更新当前字符串流
		token += string(x)
		//可打印每一步解析结果信息
		//fmt.Printf("idx: %d, x: %s, token: %s, tokens: %v\n", idx, string(x), token, tokens)
		//第一位必须是'$'或容错使用'@'
		if idx == 0 {
			if token == "$" || token == "@" {
				tokens = append(tokens, token[:])
				token = ""
				continue
			} else {
				return nil, fmt.Errorf("should start with '$'")
			}
		}
		if token == "." {
			continue
		} else if token == ".." {
			//如果是'..'递归操作符，保存这个操作
			if tokens[len(tokens)-1] != "*" {
				tokens = append(tokens, "*")
			}
			token = "."
			continue
		} else {
			// fmt.Println("else: ", string(x), token)
			// 操作[]操作符
			if strings.Contains(token, "[") {
				// fmt.Println(" contains [ ")
				if x == ']' && !strings.HasSuffix(token, "\\]") {
					if token[0] == '.' {
						tokens = append(tokens, token[1:])
					} else {
						tokens = append(tokens, token[:])
					}
					token = ""
					continue
				}
			} else {
				// fmt.Println(" doesn't contains [ ")
				if x == '.' {
					if token[0] == '.' {
						tokens = append(tokens, token[1:len(token)-1])
					} else {
						tokens = append(tokens, token[:len(token)-1])
					}
					token = "."
					continue
				}
			}
		}
	}
	if len(token) > 0 {
		if token[0] == '.' {
			token = token[1:]
			if token != "*" {
				tokens = append(tokens, token[:])
			} else if tokens[len(tokens)-1] != "*" {
				tokens = append(tokens, token[:])
			}
		} else {
			if token != "*" {
				tokens = append(tokens, token[:])
			} else if tokens[len(tokens)-1] != "*" {
				tokens = append(tokens, token[:])
			}
		}
	}
	// fmt.Println("finished tokens: ", tokens)
	// fmt.Println("================================================= done ")
	return tokens, nil
}

/*
 op: "root", "key", "idx", "range", "filter", "scan"
 通过分词数组中的单个分词，解析出相应的操作
*/
func parse_token(token string) (op string, key string, args interface{}, err error) {
	if token == "$" {
		return "root", "$", nil, nil
	}

	bracket_idx := strings.Index(token, "[")
	if bracket_idx < 0 {
		//如不包含'['则当做map的key处理
		return "key", token, nil, nil
	} else {
		//包含的话解析出key和中括号中的数据
		key = token[:bracket_idx]
		tail := token[bracket_idx:]
		if len(tail) < 3 {
			err = fmt.Errorf("len(tail) should >=3, %v", tail)
			return
		}
		tail = tail[1 : len(tail)-1]

		//fmt.Println(key, tail)
		//解析中括号中的内容，得到正确操作
		if strings.Contains(tail, "?") {
			// filter -------------------------------------------------
			op = "filter"
			if strings.HasPrefix(tail, "?(") && strings.HasSuffix(tail, ")") {
				args = strings.Trim(tail[2:len(tail)-1], " ")
			}
			return
		} else if strings.Contains(tail, ":") {
			// range ----------------------------------------------
			op = "range"
			tails := strings.Split(tail, ":")
			if len(tails) != 2 {
				err = fmt.Errorf("only support one range(from, to): %v", tails)
				return
			}
			var frm interface{}
			var to interface{}
			if frm, err = strconv.Atoi(strings.Trim(tails[0], " ")); err != nil {
				if strings.Trim(tails[0], " ") == "" {
					err = nil
				}
				frm = nil
			}
			if to, err = strconv.Atoi(strings.Trim(tails[1], " ")); err != nil {
				if strings.Trim(tails[1], " ") == "" {
					err = nil
				}
				to = nil
			}
			args = [2]interface{}{frm, to}
			return
		} else if tail == "*" {
			op = "range"
			args = [2]interface{}{nil, nil}
			return
		} else {
			// idx ------------------------------------------------
			op = "idx"
			res := []int{}
			for _, x := range strings.Split(tail, ",") {
				if i, err := strconv.Atoi(strings.Trim(x, " ")); err == nil {
					res = append(res, i)
				} else {
					return "", "", nil, err
				}
			}
			args = res
		}
	}
	return op, key, args, nil
}

func (c *Compiled) String() string {
	return fmt.Sprintf("Compiled lookup: %s", c.path)
}

//查找的实际操作接口
//obj 需要处理的json的字节数组
func (c *Compiled) Lookup(obj interface{}) (interface{}, error) {
	var err error
	var root = obj
	//遍历所有操作一步步进行
	for _, s := range c.steps {
		// "key", "idx"
		switch s.op {
		//map的键值操作
		case "key":
			obj, err = get_key(obj, s.key)
			if err != nil {
				return nil, err
			}
		//数组的下标取值操作
		case "idx":
			if len(s.key) > 0 {
				// no key `$[0].test`
				obj, err = get_key(obj, s.key)
				if err != nil {
					return nil, err
				}
			}
			//如果有中括号中有多个下标
			if len(s.args.([]int)) > 1 {
				res := []interface{}{}
				for _, x := range s.args.([]int) {
					//fmt.Println("idx ---- ", x)
					tmp, err := get_idx(obj, x)
					if err != nil {
						return nil, err
					}
					res = append(res, tmp)
				}
				obj = res
			} else if len(s.args.([]int)) == 1 {
				//只有一个下标
				//fmt.Println("idx ----------------3")
				obj, err = get_idx(obj, s.args.([]int)[0])
				if err != nil {
					return nil, err
				}
			} else {
				//fmt.Println("idx ----------------4")
				return nil, fmt.Errorf("cannot index on empty slice")
			}
		//通过范围在数组中获取数据
		case "range":
			//有key，先通过key拿到值之后再筛选范围
			if len(s.key) > 0 {
				// no key `$[:1].test`
				obj, err = get_key(obj, s.key)
				if err != nil {
					return nil, err
				}
			}
			if argsv, ok := s.args.([2]interface{}); ok == true {
				obj, err = get_range(obj, argsv[0], argsv[1])
				if err != nil {
					return nil, err
				}
			} else {
				return nil, fmt.Errorf("range args length should be 2")
			}
		//操作符过滤
		case "filter":
			obj, err = get_key(obj, s.key)
			if err != nil {
				return nil, err
			}
			obj, err = get_filtered(obj, root, s.args.(string))
			if err != nil {
				return nil, err
			}
		//通过递归操作在数据中取得所有数据
		case "scan":
			obj, err = get_recursion(obj, s.key, s.args)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("expression don't support in filter")
		}
	}
	return obj, nil
}

//数据列过滤和数据脱敏在这个函数集中处理
//mode用于分辨操作模式
//opertFunc 只对数据托名有作用。用于选择数据脱敏模式
func (c *Compiled) LookupAndOperate(obj interface{}, mode string, opertFunc string) (interface{}, error) {
	var err error
	var temp = obj
	var root = obj
	var stepLen = len(c.steps)
	var lastStep = stepLen - 1
	for i, s := range c.steps {
		// "key", "idx"

		switch s.op {
		case "key":
			if i == lastStep {
				err = operate_key(temp, s.key, mode, opertFunc)
			} else {
				temp, err = get_key(temp, s.key)
			}
			if err != nil {
				return nil, err
			}
		case "idx":
			if i == lastStep {
				err = operate_idx(temp, s.key, s.args, mode, opertFunc)
				if err != nil {
					return nil, err
				}
			} else {
				if len(s.key) > 0 {
					// no key `$[0].test`
					temp, err = get_key(temp, s.key)
					if err != nil {
						return nil, err
					}
				}

				if len(s.args.([]int)) > 1 {
					res := []interface{}{}
					for _, x := range s.args.([]int) {
						//fmt.Println("idx ---- ", x)
						tmp, err := get_idx(temp, x)
						if err != nil {
							return nil, err
						}
						res = append(res, tmp)
					}
					temp = res
				} else if len(s.args.([]int)) == 1 {
					//fmt.Println("idx ----------------3")
					temp, err = get_idx(temp, s.args.([]int)[0])
					if err != nil {
						return nil, err
					}
				} else {
					//fmt.Println("idx ----------------4")
					return nil, fmt.Errorf("cannot index on empty slice")
				}
			}
		case "range":
			if i == lastStep {
				err = operate_range(temp, s.key, s.args, mode, opertFunc)
				if err != nil {
					return nil, err
				}
			} else {
				if len(s.key) > 0 {
					// no key `$[:1].test`
					temp, err = get_key(temp, s.key)
					if err != nil {
						return nil, err
					}
				}
				if argsv, ok := s.args.([2]interface{}); ok == true {
					temp, err = get_range(temp, argsv[0], argsv[1])
					if err != nil {
						return nil, err
					}
				} else {
					return nil, fmt.Errorf("range args length should be 2")
				}
			}
		case "filter":
			if i == lastStep {
				err := operate_filter(temp, root, s.key, s.args.(string), mode, opertFunc)
				if err != nil {
					return nil, err
				}
			} else {
				temp, err = get_key(temp, s.key)
				if err != nil {
					return nil, err
				}
				temp, err = get_filtered(temp, root, s.args.(string))
				if err != nil {
					return nil, err
				}
			}
		case "scan":
			if i == lastStep {
				//初始化当前已递归遍历在第一个位置
				curr = 0
				err = operateRecursion(temp, s.key, s.args, mode, opertFunc)
			} else {
				temp, err = get_recursion(temp, s.key, s.args)
			}
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("expression don't support in filter")
		}
	}
	return obj, nil
}

//通过下标修改json对象
func operate_idx(obj interface{}, key string, args interface{}, mode string, opertFunc string) error {
	var argvs = args.([]int)
	if len(key) > 0 {
		if reflect.TypeOf(obj).Kind() == reflect.Map {
			if jsonMap, ok := obj.(map[string]interface{}); ok {
				for k, v := range jsonMap {
					if k == key {
						if reflect.TypeOf(v).Kind() != reflect.Slice {
							return fmt.Errorf("%s object is not slice", key)
						}
						var tempv = v.([]interface{})
						if mode == conf.DataFieldControl {
							var resultv []interface{}
							for w, q := range tempv {
								var isExist bool
								for _, arg := range argvs {
									if arg == w {
										isExist = true
									}
								}
								if isExist == false {
									resultv = append(resultv, q)
								}
							}
							jsonMap[k] = resultv
						}
					}
				}
			}
		} else {
			return fmt.Errorf("object is not map")
		}
	} else {
		return fmt.Errorf("key is nil")
	}
	return nil
}

//有两种情况，key为空即obj为目标数组，key不为空obj为map。obj[key]为目标数组
func operate_range(obj interface{}, key string, args interface{}, mode string, opertFunc string) error {
	switch reflect.TypeOf(obj).Kind() {
	case reflect.Slice:
		length := reflect.ValueOf(obj).Len()
		argvs := args.([2]interface{})
		left, right, err := transforRange(length, argvs[0], argvs[1])
		if err != nil {
			return err
		}
		var tempargs []int
		for i := left; i <= right; i++ {
			tempargs = append(tempargs, i)
		}
		err = operate_idx(obj, key, tempargs, mode, opertFunc)
		return err
	case reflect.Map:
		tempMap := obj.(map[string]interface{})
		length := reflect.ValueOf(tempMap[key]).Len()
		argvs := args.([2]interface{})
		left, right, err := transforRange(length, argvs[0], argvs[1])
		if err != nil {
			return err
		}
		var tempargs []int
		for i := left; i <= right; i++ {
			tempargs = append(tempargs, i)
		}
		err = operate_idx(obj, key, tempargs, mode, opertFunc)
		return err
	default:
		return fmt.Errorf("obj is not slice or map")
	}
}

//递归查找支持函数
func get_recursion(obj interface{}, key string, args interface{}) (interface{}, error) {
	if reflect.TypeOf(obj) == nil {
		return nil, ErrGetFromNullObj
	}
	//获取到所有的匹配值
	var result []interface{}
	recursion_search(obj, key, &result)
	//判断是否之后跟有表示范围的语句
	if args != nil {
		var argsv [2]interface{}
		// 分辨中括号中是单个数字还是范围
		if tempargsv, ok := args.([2]interface{}); ok == true {
			argsv = tempargsv
			tempresult, err := get_range(result, argsv[0], argsv[1])
			if err != nil {
				return nil, err
			}
			return tempresult, nil

		} else if tempargsv, ok := args.([]int); ok == true {
			var tempresult []interface{}
			for _, v := range tempargsv {
				oneResult, err := get_idx(result, v)
				if err != nil {
					return nil, err
				}
				tempresult = append(tempresult, oneResult)
			}
			return tempresult, nil
		} else {
			return nil, fmt.Errorf("range args length should be 2 or 1")
		}
	} else {
		return result, nil
	}
}

//递归查找需要调用，支持'..'操作符
func recursion_search(obj interface{}, key string, res *[]interface{}) {
	switch reflect.TypeOf(obj).Kind() {
	case reflect.Map:
		if jsonMap, ok := obj.(map[string]interface{}); ok {
			for k, v := range jsonMap {
				if k == key {
					*res = append(*res, v)
				} else {
					recursion_search(v, key, res)
				}
			}
		}
	case reflect.Slice:
		for i := 0; i < reflect.ValueOf(obj).Len(); i++ {
			tmp, _ := get_idx(obj, i)
			recursion_search(tmp, key, res)
		}
	}
}

//递归操作需要调用，具体调用模式由mode区分
func operateRecursion(obj interface{}, key string, args interface{}, mode string, opertFunc string) error {
	if reflect.TypeOf(obj) == nil {
		return ErrGetFromNullObj
	}
	var err error
	//判断是否之后跟有表示范围的语句
	if args != nil {
		var argsv [2]int
		// 分辨中括号中是单个数字还是范围
		if tempargsv, ok := args.([2]interface{}); ok == true {
			argsv[0] = tempargsv[0].(int)
			argsv[1] = tempargsv[1].(int)
			if mode == conf.DataDesensitizationControl {
				err = recursion_desensitization(obj, key, argsv[0], argsv[1], opertFunc)
			} else if mode == conf.DataFieldControl {
				recursion_del(obj, key, argsv[0], argsv[1])
			}
		} else if tempargsv, ok := args.([]int); ok == true {
			for _, v := range tempargsv {
				if mode == conf.DataDesensitizationControl {
					err = recursion_desensitization(obj, key, v, v, opertFunc)
				} else if mode == conf.DataFieldControl {
					recursion_del(obj, key, v, v)
				}
			}
		} else {
			return fmt.Errorf("range args length should be 2 or 1")
		}
	} else {
		if mode == conf.DataDesensitizationControl {
			err = recursion_desensitization(obj, key, 0, INT_MAX, opertFunc)
		} else if mode == conf.DataFieldControl {
			recursion_del(obj, key, 0, INT_MAX)
		}
	}
	if err != nil {
		return err
	} else {
		return nil
	}
}

//递归脱敏
func recursion_desensitization(obj interface{}, key string, left int, right int, opertFunc string) error {
	if curr > right {
		return nil
	}
	switch reflect.TypeOf(obj).Kind() {
	case reflect.Map:
		if jsonMap, ok := obj.(map[string]interface{}); ok {
			for k, v := range jsonMap {
				if k == key {
					if curr < left {
						curr++
					} else if curr <= right {
						curr++
						var err error
						if desensitFunc, ok := DesensitizationFuncs[opertFunc]; ok {
							err = desensitFunc(jsonMap, key)
						} else {
							return fmt.Errorf("%s not found in function map", opertFunc)
						}
						if err != nil {
							return err
						}
						continue
					} else {
						break
					}
				} else {
					err := recursion_desensitization(v, key, left, right, opertFunc)
					if err != nil {
						return err
					}
				}
			}
		}
	case reflect.Slice:
		for i := 0; i < reflect.ValueOf(obj).Len(); i++ {
			tmp, _ := get_idx(obj, i)
			err := recursion_desensitization(tmp, key, left, right, opertFunc)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

//递归列过滤
func recursion_del(obj interface{}, key string, left int, right int) {
	if curr > right {
		return
	}
	switch reflect.TypeOf(obj).Kind() {
	case reflect.Map:
		if jsonMap, ok := obj.(map[string]interface{}); ok {
			for k, v := range jsonMap {
				if k == key {
					if curr < left {
						curr++
					} else if curr <= right {
						curr++
						delete(jsonMap, k)
					} else {
						break
					}
				} else {
					recursion_del(v, key, left, right)
				}
			}
		}
	case reflect.Slice:
		for i := 0; i < reflect.ValueOf(obj).Len(); i++ {
			tmp, _ := get_idx(obj, i)
			recursion_del(tmp, key, left, right)
		}
	}
	return
}

func filter_get_from_explicit_path(obj interface{}, path string) (interface{}, error) {
	steps, err := tokenize(path)
	//fmt.Println("f: steps: ", steps, err)
	//fmt.Println(path, steps)
	if err != nil {
		return nil, err
	}
	if steps[0] != "@" && steps[0] != "$" {
		return nil, fmt.Errorf("$ or @ should in front of path")
	}
	steps = steps[1:]
	xobj := obj
	//fmt.Println("f: xobj", xobj)
	for _, s := range steps {
		op, key, args, err := parse_token(s)
		// "key", "idx"
		switch op {
		case "key":
			xobj, err = get_key(xobj, key)
			if err != nil {
				return nil, err
			}
		case "idx":
			if len(args.([]int)) != 1 {
				return nil, fmt.Errorf("don't support multiple index in filter")
			}
			xobj, err = get_key(xobj, key)
			if err != nil {
				return nil, err
			}
			xobj, err = get_idx(xobj, args.([]int)[0])
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("expression don't support in filter")
		}
	}
	return xobj, nil
}

//通过key查找对象Map中是否有对应的值
func get_key(obj interface{}, key string) (interface{}, error) {
	if reflect.TypeOf(obj) == nil {
		return nil, ErrGetFromNullObj
	}
	switch reflect.TypeOf(obj).Kind() {
	//如果传进来的obj为Map则直接取到key对应的值
	case reflect.Map:
		// if obj came from stdlib json, its highly likely to be a map[string]interface{}
		// in which case we can save having to iterate the map keys to work out if the
		// key exists
		if jsonMap, ok := obj.(map[string]interface{}); ok {
			val, exists := jsonMap[key]
			if !exists {
				return nil, fmt.Errorf("key error: %s not found in object", key)
			}
			return val, nil
		}
		for _, kv := range reflect.ValueOf(obj).MapKeys() {
			//fmt.Println(kv.String())
			if kv.String() == key {
				return reflect.ValueOf(obj).MapIndex(kv).Interface(), nil
			}
		}
		return nil, fmt.Errorf("key error: %s not found in object", key)
	case reflect.Slice:
		// 切片需要遍历所有的切片对象获得所有相应的值
		res := []interface{}{}
		for i := 0; i < reflect.ValueOf(obj).Len(); i++ {
			tmp, _ := get_idx(obj, i)
			if v, err := get_key(tmp, key); err == nil {
				res = append(res, v)
			}
		}
		return res, nil
	default:
		return nil, fmt.Errorf("object is not map or slice")
	}
}

//通过key操作json对象
func operate_key(obj interface{}, key string, mode string, opertFunc string) error {
	if reflect.TypeOf(obj) == nil {
		return ErrGetFromNullObj
	}

	switch reflect.TypeOf(obj).Kind() {
	case reflect.Map:
		// if obj came from stdlib json, its highly likely to be a map[string]interface{}
		// in which case we can save having to iterate the map keys to work out if the
		// key exists
		if jsonMap, ok := obj.(map[string]interface{}); ok {
			_, exists := jsonMap[key]
			if !exists {
				return fmt.Errorf("key error: %s not found in object", key)
			}
			if mode == conf.DataDesensitizationControl {
				var err error
				if desensitFunc, ok := DesensitizationFuncs[opertFunc]; ok {
					err = desensitFunc(jsonMap, key)
				} else {
					return fmt.Errorf("%s not found in function map", opertFunc)
				}
				if err != nil {
					return err
				}
				return nil
			} else if mode == conf.DataFieldControl {
				delete(jsonMap, key)
				return nil
			} else {
				return nil
			}
		}
	case reflect.Slice:
		// slice we should get from all objects in it.
		for i := 0; i < reflect.ValueOf(obj).Len(); i++ {
			tmp, _ := get_idx(obj, i)

			if mode == conf.DataDesensitizationControl {
				if err := operate_key(tmp, key, conf.DataDesensitizationControl, opertFunc); err == nil {
				} else {
					return err
				}
			} else if mode == conf.DataFieldControl {
				if err := operate_key(tmp, key, conf.DataFieldControl, opertFunc); err == nil {
				} else {
					return err
				}
			}
		}
		return nil
	default:
		return fmt.Errorf("object is not map")
	}
	return nil
}

//脱敏实际操作函数，通过传过来的脱敏规则，进行脱敏
func handle_desensitization(jsonMap map[string]interface{}, key string, rule desensitization) error {
	value := []rune(jsonMap[key].(string))
	valueLen := len(value)
	if rule.start > valueLen {
		return fmt.Errorf("start pos error: %s is over the value length", rule.start)
	}
	for i := rule.start; i < rule.start+rule.size && i < valueLen; i++ {
		value[i] = int32(rule.displayChar[0])
	}
	jsonMap[key] = string(value)
	return nil
}

//车牌号脱敏函数
func carNumberDesensitization(jsonMap map[string]interface{}, key string) error {
	//普通燃油车牌号过滤方案
	fuelCar, _ := regexp.MatchString(
		`[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼使领A-Z]{1}[A-Z]{1}[A-HJ-NP-Z0-9]{4}[A-HJ-NP-Z0-9挂学警港澳]{1}`,
		jsonMap[key].(string))
	var rule desensitization
	if fuelCar {
		rule = desensitization{
			displayChar: "*",
			start:       1,
			size:        3,
		}
	} else {
		return fmt.Errorf("carnumber error")
	}
	err := handle_desensitization(jsonMap, key, rule)
	return err
}

//手机号脱敏函数
func phoneDesensitization(jsonMap map[string]interface{}, key string) error {
	phoneLen := len(jsonMap[key].(string))
	var rule desensitization
	//普通11位电话号码过滤规范
	if phoneLen == 11 {
		rule = desensitization{
			displayChar: "*",
			start:       3,
			size:        4,
		}
	} else if phoneLen == 12 {
		rule = desensitization{
			displayChar: "*",
			start:       4,
			size:        4,
		}
	} else if phoneLen == 7 || phoneLen == 6 {
		rule = desensitization{
			displayChar: "*",
			start:       1,
			size:        4,
		}
	} else if phoneLen <= 5 {
		return nil
	} else {
		return fmt.Errorf("phonenumber error")
	}
	err := handle_desensitization(jsonMap, key, rule)
	return err
}

//身份证脱敏函数
func idCardNumberDesensitization(jsonMap map[string]interface{}, key string) error {
	idCardLen := len(jsonMap[key].(string))
	var rule desensitization
	//不同身份证过滤方法
	//大陆身份证
	if idCardLen == 18 {
		rule = desensitization{
			displayChar: "*",
			start:       6,
			size:        8,
		}
	} else if idCardLen == 8 || idCardLen == 7 || idCardLen == 10 { //香港台湾身份证
		rule = desensitization{
			displayChar: "*",
			start:       1,
			size:        4,
		}
	} else { //其他情况
		rule = desensitization{
			displayChar: "*",
			start:       1,
			size:        4,
		}
	}
	err := handle_desensitization(jsonMap, key, rule)
	return err
}

//名字脱敏函数
func nameDesensitization(jsonMap map[string]interface{}, key string) error {
	value := []rune(jsonMap[key].(string))
	idCardLen := len(value)
	var rule desensitization
	//不同身份证过滤方法
	//大陆身份证
	if idCardLen == 2 {
		rule = desensitization{
			displayChar: "*",
			start:       1,
			size:        1,
		}
	} else { //其他情况
		rule = desensitization{
			displayChar: "*",
			start:       1,
			size:        idCardLen - 2,
		}
	}
	err := handle_desensitization(jsonMap, key, rule)
	return err
}

//通过下标获得切片中的元素
func get_idx(obj interface{}, idx int) (interface{}, error) {
	switch reflect.TypeOf(obj).Kind() {
	case reflect.Slice:
		length := reflect.ValueOf(obj).Len()
		if idx >= 0 {
			if idx >= length {
				return nil, fmt.Errorf("index out of range: len: %v, idx: %v", length, idx)
			}
			return reflect.ValueOf(obj).Index(idx).Interface(), nil
		} else {
			// < 0
			_idx := length + idx
			if _idx < 0 {
				return nil, fmt.Errorf("index out of range: len: %v, idx: %v", length, idx)
			}
			return reflect.ValueOf(obj).Index(_idx).Interface(), nil
		}
	default:
		return nil, fmt.Errorf("object is not Slice")
	}
}

//为了可以支持负数范围表示方法
//通过切片实际长度和传进来的范围，转换为合理的范围
func transforRange(len int, frm interface{}, to interface{}) (int, int, error) {
	_frm := 0
	_to := len
	if frm == nil {
		frm = 0
	}
	if to == nil {
		to = len - 1
	}
	if fv, ok := frm.(int); ok == true {
		if fv < 0 {
			_frm = len + fv
		} else {
			_frm = fv
		}
	}
	if tv, ok := to.(int); ok == true {
		if tv < 0 {
			_to = len + tv + 1
		} else {
			_to = tv + 1
		}
	}
	if _frm < 0 || _frm >= len {
		return -1, -1, fmt.Errorf("index [from] out of range: len: %v, from: %v", len, frm)
	}
	if _to < 0 || _to > len {
		return -1, -1, fmt.Errorf("index [to] out of range: len: %v, to: %v", len, to)
	}
	return _frm, _to, nil
}

//在切片中通过范围获得范围中的值
func get_range(obj, frm, to interface{}) (interface{}, error) {
	switch reflect.TypeOf(obj).Kind() {
	case reflect.Slice:
		length := reflect.ValueOf(obj).Len()
		_frm, _to, err := transforRange(length, frm, to)
		if err != nil {
			return nil, err
		}
		//fmt.Println("_frm, _to: ", _frm, _to)
		res_v := reflect.ValueOf(obj).Slice(_frm, _to)

		return res_v.Interface(), nil
	default:
		return nil, fmt.Errorf("object is not Slice")
	}
}

func regFilterCompile(rule string) (*regexp.Regexp, error) {
	runes := []rune(rule)
	if len(runes) <= 2 {
		return nil, errors.New("empty rule")
	}

	if runes[0] != '/' || runes[len(runes)-1] != '/' {
		return nil, errors.New("invalid syntax. should be in `/pattern/` form")
	}
	runes = runes[1 : len(runes)-1]
	return regexp.Compile(string(runes))
}

//修改过滤操作
func operate_filter(obj interface{}, root interface{}, key string, filter string, mode string, opertFunc string) error {
	opertObj, err := get_key(obj, key)
	if err != nil {
		return err
	}
	lp, op, rp, err := parse_filter(filter)
	if err != nil {
		return err
	}

	res := []interface{}{}

	switch reflect.TypeOf(opertObj).Kind() {
	case reflect.Slice:
		obj2 := obj.(map[string]interface{})
		if mode == conf.DataFieldControl {
			for i := 0; i < reflect.ValueOf(opertObj).Len(); i++ {
				tmp := reflect.ValueOf(opertObj).Index(i).Interface()
				ok, err := eval_filter(tmp, root, lp, op, rp)
				if err != nil {
					return err
				}
				if ok == false {
					res = append(res, tmp)
				}
			}
			obj2[key] = res
		} else if mode == conf.DataDesensitizationControl {
			return fmt.Errorf("not DesensitizationControl on json object")
		}
		return nil
	case reflect.Map:
		opertObj2 := obj.(map[string]interface{})
		ok, err := eval_filter(opertObj, root, lp, op, rp)
		if err != nil {
			return err
		}
		if ok == true {
			if mode == conf.DataFieldControl {
				delete(opertObj2, key)
			} else if mode == conf.DataDesensitizationControl {
				return fmt.Errorf("not DesensitizationControl on json object")
			}
		}
	default:
		return fmt.Errorf("don't support filter on this type: %v", reflect.TypeOf(obj).Kind())
	}

	return nil
}

func get_filtered(obj, root interface{}, filter string) ([]interface{}, error) {
	lp, op, rp, err := parse_filter(filter)
	if err != nil {
		return nil, err
	}

	res := []interface{}{}

	switch reflect.TypeOf(obj).Kind() {
	case reflect.Slice:
		if op == "=~" {
			// regexp
			pat, err := regFilterCompile(rp)
			if err != nil {
				return nil, err
			}

			for i := 0; i < reflect.ValueOf(obj).Len(); i++ {
				tmp := reflect.ValueOf(obj).Index(i).Interface()
				ok, err := eval_reg_filter(tmp, root, lp, pat)
				if err != nil {
					return nil, err
				}
				if ok == true {
					res = append(res, tmp)
				}
			}
		} else {
			for i := 0; i < reflect.ValueOf(obj).Len(); i++ {
				tmp := reflect.ValueOf(obj).Index(i).Interface()
				ok, err := eval_filter(tmp, root, lp, op, rp)
				if err != nil {
					return nil, err
				}
				if ok == true {
					res = append(res, tmp)
				}
			}
		}
		return res, nil
	case reflect.Map:
		if op == "=~" {
			// regexp
			pat, err := regFilterCompile(rp)
			if err != nil {
				return nil, err
			}

			for _, kv := range reflect.ValueOf(obj).MapKeys() {
				tmp := reflect.ValueOf(obj).MapIndex(kv).Interface()
				ok, err := eval_reg_filter(tmp, root, lp, pat)
				if err != nil {
					return nil, err
				}
				if ok == true {
					res = append(res, tmp)
				}
			}
		} else {
			ok, err := eval_filter(obj, root, lp, op, rp)
			if err != nil {
				return nil, err
			}
			if ok == true {
				res = append(res, obj)
			}
			return res, nil
		}
	default:
		return nil, fmt.Errorf("don't support filter on this type: %v", reflect.TypeOf(obj).Kind())
	}

	return res, nil
}

// @.isbn                 => @.isbn, exists, nil
// @.price < 10           => @.price, <, 10
// @.price <= $.expensive => @.price, <=, $.expensive
// @.author =~ /.*REES/i  => @.author, match, /.*REES/i

func parse_filter(filter string) (lp string, op string, rp string, err error) {
	tmp := ""

	stage := 0
	str_embrace := false
	for idx, c := range filter {
		switch c {
		case '\'':
			if str_embrace == false {
				str_embrace = true
			} else {
				switch stage {
				case 0:
					lp = tmp
				case 1:
					op = tmp
				case 2:
					rp = tmp
				}
				tmp = ""
			}
		case ' ':
			if str_embrace == true {
				tmp += string(c)
				continue
			}
			switch stage {
			case 0:
				lp = tmp
			case 1:
				op = tmp
			case 2:
				rp = tmp
			}
			tmp = ""

			stage += 1
			if stage > 2 {
				return "", "", "", errors.New(fmt.Sprintf("invalid char at %d: `%c`", idx, c))
			}
		default:
			tmp += string(c)
		}
	}
	if tmp != "" {
		switch stage {
		case 0:
			lp = tmp
			op = "exists"
		case 1:
			op = tmp
		case 2:
			rp = tmp
		}
		tmp = ""
	}
	return lp, op, rp, err
}

func parse_filter_v1(filter string) (lp string, op string, rp string, err error) {
	tmp := ""
	istoken := false
	for _, c := range filter {
		if istoken == false && c != ' ' {
			istoken = true
		}
		if istoken == true && c == ' ' {
			istoken = false
		}
		if istoken == true {
			tmp += string(c)
		}
		if istoken == false && tmp != "" {
			if lp == "" {
				lp = tmp[:]
				tmp = ""
			} else if op == "" {
				op = tmp[:]
				tmp = ""
			} else if rp == "" {
				rp = tmp[:]
				tmp = ""
			}
		}
	}
	if tmp != "" && lp == "" && op == "" && rp == "" {
		lp = tmp[:]
		op = "exists"
		rp = ""
		err = nil
		return
	} else if tmp != "" && rp == "" {
		rp = tmp[:]
		tmp = ""
	}
	return lp, op, rp, err
}

func eval_reg_filter(obj, root interface{}, lp string, pat *regexp.Regexp) (res bool, err error) {
	if pat == nil {
		return false, errors.New("nil pat")
	}
	lp_v, err := get_lp_v(obj, root, lp)
	if err != nil {
		return false, err
	}
	switch v := lp_v.(type) {
	case string:
		return pat.MatchString(v), nil
	default:
		return false, errors.New("only string can match with regular expression")
	}
}

func get_lp_v(obj, root interface{}, lp string) (interface{}, error) {
	var lp_v interface{}
	if strings.HasPrefix(lp, "@.") {
		return filter_get_from_explicit_path(obj, lp)
	} else if strings.HasPrefix(lp, "$.") {
		return filter_get_from_explicit_path(root, lp)
	} else {
		lp_v = lp
	}
	return lp_v, nil
}

func eval_filter(obj, root interface{}, lp, op, rp string) (res bool, err error) {
	lp_v, err := get_lp_v(obj, root, lp)

	if op == "exists" {
		return lp_v != nil, nil
	} else if op == "=~" {
		return false, fmt.Errorf("not implemented yet")
	} else {
		//匹配in,not in操作符
		var InOperatRegexp, _ = regexp.Compile("{.*}")
		if InOperatRegexp.Match([]byte(rp)) {
			var rp_vs []string
			rp = rp[1 : len(rp)-1]
			rp_vs = strings.Split(rp, ",")
			for k, v := range rp_vs {
				var tempv interface{}
				if strings.HasPrefix(rp, "@.") {
					tempv, err = filter_get_from_explicit_path(obj, v)
				} else if strings.HasPrefix(rp, "$.") {
					tempv, err = filter_get_from_explicit_path(root, v)
				} else {
					tempv = v
				}
				rp_vs[k] = tempv.(string)
			}
			return contain_any(lp_v, rp_vs, op)
		} else {
			//匹配 ==,>,<,>=,<=
			var rp_v interface{}
			if strings.HasPrefix(rp, "@.") {
				rp_v, err = filter_get_from_explicit_path(obj, rp)
			} else if strings.HasPrefix(rp, "$.") {
				rp_v, err = filter_get_from_explicit_path(root, rp)
			} else {
				rp_v = rp
			}
			//fmt.Printf("lp_v: %v, rp_v: %v\n", lp_v, rp_v)
			return cmp_any(lp_v, rp_v, op)
		}
	}
}

func isNumber(o interface{}) bool {
	switch v := o.(type) {
	case int, int8, int16, int32, int64:
		return true
	case uint, uint8, uint16, uint32, uint64:
		return true
	case float32, float64:
		return true
	case string:
		_, err := strconv.ParseFloat(v, 64)
		if err == nil {
			return true
		} else {
			return false
		}
	}
	return false
}

func contain_any(obj1 interface{}, obj2 []string, op string) (bool, error) {
	switch op {
	case "in":
		for _, v := range obj2 {
			ok, _ := cmp_any(obj1, v, "==")
			if ok {
				return true, nil
			}
		}
		return false, nil
	case "noin":
		for _, v := range obj2 {
			ok, _ := cmp_any(obj1, v, "==")
			if ok {
				return false, nil
			}
		}
		return true, nil
	default:
		return false, fmt.Errorf("op should only be in or noin")
	}
}

func cmp_any(obj1, obj2 interface{}, op string) (bool, error) {
	switch op {
	case "<", "<=", "==", ">=", ">":
	default:
		return false, fmt.Errorf("op should only be <, <=, ==, >= and >")
	}

	var exp string
	if isNumber(obj1) && isNumber(obj2) {
		exp = fmt.Sprintf(`%v %s %v`, obj1, op, obj2)
	} else {
		exp = fmt.Sprintf(`"%v" %s "%v"`, obj1, op, obj2)
	}
	//fmt.Println("exp: ", exp)
	fset := token.NewFileSet()
	res, err := types.Eval(fset, nil, 0, exp)
	if err != nil {
		return false, err
	}
	if res.IsValue() == false || (res.Value.String() != "false" && res.Value.String() != "true") {
		return false, fmt.Errorf("result should only be true or false")
	}
	if res.Value.String() == "true" {
		return true, nil
	}

	return false, nil
}
