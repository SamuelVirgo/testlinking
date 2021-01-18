package main

import (
	"encoding/csv"

	"encoding/json"

	"os"

	"strconv"

	"strings"

	"time"
)

type Date struct{ time.Time }

func (d *Date) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}
	t, err := time.Parse("2006-01-02Z0700", s)
	if err != nil {
		return err
	}
	*d = Date{t}
	return nil
}

type File struct {
	FilePath  string
	CSVReader *csv.Reader
	// copy of file
	*os.File
}

type CSVFileWrapper File

func (f *CSVFileWrapper) Read() (record []string, err error) {
	if f.CSVReader == nil {
		f.CSVReader = csv.NewReader(f.File)
	}

	return f.CSVReader.Read()
}

type NonStrictInt int

func (ri *NonStrictInt) UnmarshalJSON(buf []byte) (err error) {
	var i int

	// Attempt to convert string to int.
	if buf[0] == '"' {
		var s string
		if err = json.Unmarshal(buf, &s); err != nil {
			return err
		}

		if s == "" {
			s = "0"
		}

		if i, err = strconv.Atoi(s); err != nil {
			return err
		}
	} else {
		if err = json.Unmarshal(buf, &i); err != nil {
			return err
		}
	}

	*ri = NonStrictInt(i)
	return nil
}

type NonStrictFloat float64

func (ri *NonStrictFloat) UnmarshalJSON(buf []byte) (err error) {
	var f float64

	// Attempt to convert string to int.
	if buf[0] == '"' {
		var s string
		if err = json.Unmarshal(buf, &s); err != nil {
			return err
		}

		if s == "" {
			s = "0"
		}

		if f, err = strconv.ParseFloat(s, 64); err != nil {
			return err
		}
	} else {
		if err = json.Unmarshal(buf, &f); err != nil {
			return err
		}
	}

	*ri = NonStrictFloat(f)
	return nil
}

type NonStrictBool bool

func (ri *NonStrictBool) UnmarshalJSON(buf []byte) (err error) {
	var b bool
	if b, err = strconv.ParseBool(strings.ToLower(strings.Trim(string(buf), "\""))); err != nil {
		return err
	}

	*ri = NonStrictBool(b)
	return nil
}

type NonStrictString string

func (ri *NonStrictString) UnmarshalJSON(buf []byte) (err error) {
	var s string
	if buf[0] == '"' {
		if err = json.Unmarshal(buf, &s); err != nil {
			return err
		}
	} else {
		s = string(buf)
	}

	*ri = NonStrictString(s)
	return nil
}
