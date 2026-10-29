package main

import (
    "bytes"
    "crypto/sha256"
    "fmt"
    "go/parser"
    "go/scanner"
    "go/token"
    "io"
    "os"
    "path/filepath"
    "runtime"
    "syscall"
)

type AuditMetadata struct {
    Mode uint32 `json:"mode"`
    UID uint32 `json:"uid"`
    GID uint32 `json:"gid"`
}
type AuditFile struct {
    SHA256 string `json:"sha256"`
    Metadata AuditMetadata `json:"metadata"`
}
type AuditParseError struct {
    Offset int `json:"offset"`
    Line int `json:"line"`
    Column int `json:"column"`
    Message string `json:"message"`
}
type AuditParse struct {
    Parser string `json:"parser"`
    SHA256 string `json:"sha256"`
    Valid bool `json:"valid"`
    Errors []AuditParseError `json:"errors"`
}
func auditMetadata(info os.FileInfo) AuditMetadata {
    s := info.Sys().(*syscall.Stat_t)
    return AuditMetadata{s.Mode,s.Uid,s.Gid}
}
func auditHash(raw []byte) string { return fmt.Sprintf("%x",sha256.Sum256(raw)) }
func auditSnapshot(root string) (map[string]AuditFile,error) {
    files:=map[string]AuditFile{}
    err:=filepath.Walk(root,func(path string,info os.FileInfo,err error) error {
        if err!=nil{return err}
        if info.IsDir(){return nil}
        if !info.Mode().IsRegular(){return fmt.Errorf("nonregular audit input: %s",path)}
        rel,err:=filepath.Rel(root,path);if err!=nil{return err}
        raw,err:=os.ReadFile(path);if err!=nil{return err}
        files[filepath.ToSlash(rel)]=AuditFile{auditHash(raw),auditMetadata(info)}
        return nil
    })
    return files,err
}
func auditParseTarget(path string) (AuditParse,error) {
    result:=AuditParse{Parser:"go version "+runtime.Version()+" "+runtime.GOOS+"/"+runtime.GOARCH,Errors:[]AuditParseError{}}
    raw,err:=os.ReadFile(path);if err!=nil{return result,err}
    result.SHA256=auditHash(raw)
    fset:=token.NewFileSet()
    _,err=parser.ParseFile(fset,path,raw,parser.AllErrors)
    if err==nil{result.Valid=true;return result,nil}
    errors,ok:=err.(scanner.ErrorList);if !ok{return result,err}
    file:=fset.File(token.Pos(1));if file==nil{return result,fmt.Errorf("missing physical parser file")}
    for _,e:=range errors {
        offset:=e.Pos.Offset
        if offset<0||offset>len(raw){return result,fmt.Errorf("parser offset outside source")}
        physical:=file.PositionFor(file.Pos(offset),false)
        result.Errors=append(result.Errors,AuditParseError{offset,physical.Line,physical.Column,e.Msg})
    }
    return result,nil
}
func auditRestoreTarget(path string, original []byte, metadata AuditMetadata) error {
    info,err:=os.Lstat(path);if err!=nil{return err}
    if !info.Mode().IsRegular(){return fmt.Errorf("audit restore target is not regular")}
    f,err:=os.OpenFile(path,os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW,0)
    if err!=nil{return err}
    n,writeErr:=f.Write(original)
    if writeErr==nil&&n!=len(original){writeErr=io.ErrShortWrite}
    if writeErr==nil{writeErr=syscall.Fchown(int(f.Fd()),int(metadata.UID),int(metadata.GID))}
    if writeErr==nil{writeErr=syscall.Fchmod(int(f.Fd()),metadata.Mode&07777)}
    closeErr:=f.Close();if writeErr!=nil{return writeErr};if closeErr!=nil{return closeErr}
    after,err:=os.Lstat(path);if err!=nil{return err}
    restored,err:=os.ReadFile(path);if err!=nil{return err}
    if !after.Mode().IsRegular()||auditMetadata(after)!=metadata||!bytes.Equal(restored,original){
        return fmt.Errorf("audit target bytes or mode/uid/gid did not restore")
    }
    return nil
}
