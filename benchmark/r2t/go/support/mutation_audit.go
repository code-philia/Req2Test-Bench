// Standalone audit operations. The source engine and parser/restorer stay separate.
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "os"
    "os/exec"
    "path/filepath"
    "reflect"
    "strconv"
    "strings"
)

const auditArea = "/r2t-go/run/mutation-audit"
const auditRoot = auditArea + "/original"
const auditRequestPath = "/r2t-go/run/work/_bench/go/mutation-audit-request.json"
const auditEngine = "/work/_bench/go/support/mutate.go"

type auditInput struct {
    SHA256 string `json:"sha256"`
    Data []byte `json:"data"`
    Mode uint32 `json:"mode"`
    Removable bool `json:"removable"`
}
type auditContext struct {
    PackageDir string `json:"package_dir"`
    PackageName string `json:"package_name"`
    GluePath string `json:"glue_path"`
    Tags []string `json:"go_build_tags"`
    Answers []string `json:"answers"`
    ProductionFiles []string `json:"production_files"`
}
type auditDescriptor struct {
    ID string `json:"id"`
    File string `json:"file"`
    Operator string `json:"operator"`
    StartLine int `json:"start_line"`
    StartCol int `json:"start_col"`
    EndLine int `json:"end_line"`
    EndCol int `json:"end_col"`
    Original string `json:"original"`
    Mutated string `json:"mutated"`
}
type auditRequest struct {
    Files map[string]auditInput `json:"files"`
    Contexts []auditContext `json:"contexts"`
    Mutants []auditDescriptor `json:"mutants"`
}
func must(err error) { if err != nil { panic(err) } }
func require(ok bool, reason string) { if !ok { panic(reason) } }
func path(root, relative string) string {
    require(relative != "" && !filepath.IsAbs(relative) && filepath.Clean(relative)==relative && relative!=".." && !strings.HasPrefix(relative,"../"),"invalid audit relative path")
    return filepath.Join(root,relative)
}
func snapshot(root string) map[string]AuditFile { value,err:=auditSnapshot(root);must(err);return value }
func metadataFor(relative string,input auditInput) AuditMetadata {
    if input.Removable { return AuditMetadata{input.Mode,uint32(os.Geteuid()),uint32(os.Getegid())} }
    original:=path("/work",relative);info,err:=os.Lstat(original);must(err)
    require(info.Mode().IsRegular(),"original source is not regular")
    raw,err:=os.ReadFile(original);must(err)
    require(auditHash(raw)==input.SHA256 && auditMetadata(info).Mode==input.Mode,"original bytes/mode differ")
    return auditMetadata(info)
}
var originalFacts map[string]AuditFile
func expected(req auditRequest, answers []string) map[string]AuditFile {
    selected:=map[string]bool{};for _,p:=range answers {selected[p]=true}
    result:=map[string]AuditFile{}
    for rel,input:=range req.Files {
        if answers!=nil && input.Removable && !selected[rel] {continue}
        result[rel]=originalFacts[rel]
    }
    return result
}
func materialize(root string,req auditRequest,wanted map[string]AuditFile) {
    must(os.MkdirAll(root,0700))
    for rel,fact:=range wanted {
        target:=path(root,rel);must(os.MkdirAll(filepath.Dir(target),0700))
        f,err:=os.OpenFile(target,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600);must(err);must(f.Close())
        must(auditRestoreTarget(target,req.Files[rel].Data,fact.Metadata))
    }
    require(reflect.DeepEqual(snapshot(root),wanted),"staged source differs from original bytes/metadata")
}
func viewRoot(i int) string {return fmt.Sprintf("%s/views/%d",auditArea,i)}
func checkViews(req auditRequest) {
    for i,c:=range req.Contexts {require(reflect.DeepEqual(snapshot(viewRoot(i)),expected(req,c.Answers)),"original compile view changed")}
}
func engineRequest(req auditRequest,target string) map[string]any {
    contexts:=[]map[string]any{}
    for i,c:=range req.Contexts {
        active:=false;for _,p:=range c.ProductionFiles {if p==target {active=true}}
        if active {contexts=append(contexts,map[string]any{"root":viewRoot(i),"package_dir":c.PackageDir,"package_name":c.PackageName,"glue_path":c.GluePath,"go_build_tags":c.Tags})}
    }
    require(len(contexts)>0,"target has no admitted compile context")
    hashes:=map[string]string{};for p,f:=range req.Files {hashes[p]=f.SHA256}
    return map[string]any{"contexts":contexts,"source_files":hashes}
}
func saveJSON(file string,value any) {raw,err:=json.Marshal(value);must(err);must(os.WriteFile(file,raw,0600))}
func operation(req auditRequest,action string,index int,result map[string]any) {
    if action=="setup" {
        _,err:=os.Lstat(auditArea);require(os.IsNotExist(err),"audit area is not fresh")
        must(os.Mkdir(auditArea,0700));result["owned"]=true
        for _,dir:=range []string{"cache","tmp","views"} {must(os.Mkdir(auditArea+"/"+dir,0700))}
        materialize(auditRoot,req,expected(req,nil))
        for i,c:=range req.Contexts {materialize(viewRoot(i),req,expected(req,c.Answers))}
        parser,err:=exec.Command("/usr/local/go/bin/go","version").Output();must(err)
        result["runtime_parser"]=strings.TrimSpace(string(parser))
        result["before"]=snapshot(auditRoot)
        return
    }
    if action=="retire" {
        result["before"]=snapshot(auditRoot);checkViews(req)
        must(os.RemoveAll(auditArea));_,err:=os.Lstat(auditArea)
        require(os.IsNotExist(err),"audit private source/cache/tmp absence is unproved")
        result["private_analysis_removed"]=true
        return
    }
    require(index>=0&&index<len(req.Mutants),"invalid audit descriptor index")
    d:=req.Mutants[index];target:=path(auditRoot,d.File)
    result["mutant_id"]=d.ID;result["before"]=snapshot(auditRoot)
    if action!="restore" {checkViews(req)}
    switch action {
    case "apply":
        require(reflect.DeepEqual(snapshot(auditRoot),expected(req,nil)),"audit original is not pristine before apply")
        requestFile:=auditArea+"/context.json";saveJSON(requestFile,engineRequest(req,d.File))
        argv:=[]string{"run","-p=1",auditEngine,"--operator-profile","v2","--root",auditRoot,"--build-contexts",requestFile,
            "--apply-file",d.File,"--start-line",strconv.Itoa(d.StartLine),"--start-col",strconv.Itoa(d.StartCol),
            "--operator",d.Operator,"--original",d.Original,"--mutated",d.Mutated,"--out",d.File}
        cmd:=exec.Command("/usr/local/go/bin/go",argv...);cmd.Dir="/r2t-go/run/work"
        cmd.Env=append(os.Environ(),"GOCACHE="+auditArea+"/cache","GOTMPDIR="+auditArea+"/tmp","TMPDIR="+auditArea+"/tmp")
        stdout,err:=os.Create(auditArea+"/engine.stdout");must(err)
        stderr,err:=os.Create(auditArea+"/engine.stderr");must(err)
        cmd.Stdout=stdout;cmd.Stderr=stderr;runErr:=cmd.Run();must(stdout.Close());must(stderr.Close())
        out,err:=os.ReadFile(auditArea+"/engine.stdout");must(err);errors,err:=os.ReadFile(auditArea+"/engine.stderr");must(err)
        result["engine_stdout"]=string(out);result["engine_stderr"]=string(errors)
        result["engine_argv"]=append([]string{"/usr/local/go/bin/go"},argv...)
        result["engine_returncode"]=cmd.ProcessState.ExitCode()
        if runErr!=nil {panic(fmt.Sprintf("source applier failed: %v",runErr))}
    case "parse":
        parsed,err:=auditParseTarget(target);must(err);result["parse"]=parsed
    case "restore":
        // Preserve streamed engine diagnostics even if the earlier apply
        // operation was killed before it could return its JSON response.
        for _,name:=range []string{"stdout","stderr"} {
            raw,err:=os.ReadFile(auditArea+"/engine."+name)
            if err==nil {result["prior_engine_"+name]=string(raw)} else if !os.IsNotExist(err) {must(err)}
        }
        must(auditRestoreTarget(target,req.Files[d.File].Data,metadataFor(d.File,req.Files[d.File])))
        checkViews(req)
    default:panic("undeclared audit operation")
    }
    raw,err:=os.ReadFile(target);must(err);result["target"]=raw
    result["after"]=snapshot(auditRoot)
}
func main() {
    result:=map[string]any{"ok":false,"owned":false}
    defer func(){
        if failure:=recover();failure!=nil {result["error"]=fmt.Sprint(failure)}
        must(json.NewEncoder(os.Stdout).Encode(result))
    }()
    require(len(os.Args)==2||len(os.Args)==3,"audit needs one declared operation")
    action:=os.Args[1];index:=-1
    if len(os.Args)==3 {var err error;index,err=strconv.Atoi(os.Args[2]);must(err)}
    require((action=="setup"||action=="retire")==(len(os.Args)==2),"operation index shape differs")
    raw,err:=os.ReadFile(auditRequestPath);must(err);var req auditRequest
    decoder:=json.NewDecoder(bytes.NewReader(raw));decoder.DisallowUnknownFields();must(decoder.Decode(&req))
    require(len(req.Files)>0&&len(req.Contexts)>0,"missing audit source/context authority")
    result["operation"]=action
    // Authenticate immutable input once per operation, then derive each exact
    // compile view from those facts instead of rereading /work for every view.
    originalFacts=map[string]AuditFile{}
    for rel,input:=range req.Files {
        require(auditHash(input.Data)==input.SHA256,"request bytes/hash differ")
        originalFacts[rel]=AuditFile{input.SHA256,metadataFor(rel,input)}
    }
    operation(req,action,index,result);result["ok"]=true
}
