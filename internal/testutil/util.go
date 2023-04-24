package testutil

import (
	"reflect"
	"time"
)

func AllFieldsNotNilOrEmptyStruct(s interface{}) bool {
	val := reflect.ValueOf(s)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		switch field.Kind() {
		case reflect.Ptr:
			if field.IsNil() {
				return false
			}
		case reflect.Struct:
			if reflect.DeepEqual(field.Interface(), reflect.Zero(field.Type()).Interface()) {
				return false
			}
		case reflect.String:
			if field.Len() == 0 {
				return false
			}
		case reflect.Slice, reflect.Array, reflect.Map:
			if field.Len() == 0 {
				return false
			}
		}
	}
	return true
}

func Ptr[T any](input T) *T {
	return &input
}

func TimeMustParse(layout, value string) time.Time {
	parsedTime, err := time.Parse(layout, value)
	if err != nil {
		panic(err)
	}
	return parsedTime
}
