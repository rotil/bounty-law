# by m4ll0k - github.com/m4ll0k 
# (@m4ll0k2)

import requests 
from jsbeautifier import beautify
import sys,re
import string 
import os.path

blacklisted = [
"await",
"break",
"case",
"catch",
"class",
"const",
"continue",
"debugger",
"default",
"delete",
"do",
"else",
"enum",
"export",
"extends",
"false",
"finally",
"for",
"function",
"if",
"implements",
"import",
"in",
"instanceof",
"interface",
"let",
"new",
"null",
"package",
"private",
"protected",
"public",
"return",
"super",
"switch",
"static",
"this",
"throw",
"try",
"true",
"typeof",
"var",
"void",
"while",
"with",
"abstract",
"else",
"instanceof",
"super",
"boolean",
"enum",
"int",
"switch",
"break",
"export",
"interface",
"synchronized",
"byte",
"extends",
"let",
"this",
"case",
"false",
"long",
"throw",
"catch",
"final",
"native",
"throws",
"char",
"finally",
"new",
"transient",
"class",
"float",
"null",
"true",
"const",
"for",
"package",
"try",
"continue",
"function",
"private",
"typeof",
"debugger",
"goto",
"protected",
"var",
"default",
"if",
"public",
"void",
"delete",
"implements",
"return",
"volatile",
"do",
"import",
"short",
"while",
"double",
"in",
"static",
"with",
"alert",
"frames",
"outerheight",
"all",
"framerate",
"outerwidth",
"anchor",
"function",
"packages",
"anchors",
"getclass",
"pagexoffset",
"area",
"hasownproperty",
"pageyoffset",
"array",
"hidden",
"parent",
"assign",
"history",
"parsefloat",
"blur",
"image",
"parseint",
"button",
"images",
"password",
"checkbox",
"infinity",
"pkcs11",
"clearinterval",
"isfinite",
"plugin",
"cleartimeout",
"isnan",
"prompt",
"clientinformation",
"isprototypeof",
"propertyisenum",
"close",
"java",
"prototype",
"closed",
"javaarray",
"radio",
"confirm",
"javaclass",
"reset",
"constructor",
"javaobject",
"screenx",
"crypto",
"javapackage",
"screeny",
"date",
"innerheight",
"scroll",
"decodeuri",
"innerwidth",
"secure",
"decodeuricomponent",
"layer",
"select",
"defaultstatus",
"layers",
"self",
"document",
"length",
"setinterval",
"element",
"link",
"settimeout",
"elements",
"location",
"status",
"embed",
"math",
"string",
"embeds",
"mimetypes",
"submit",
"encodeuri",
"name",
"taint",
"encodeuricomponent",
"nan",
"text",
"escape",
"navigate",
"textarea",
"eval",
"navigator",
"top",
"event",
"number",
"tostring",
"fileupload",
"object",
"undefined",
"focus",
"offscreenbuffering",
"unescape",
"form",
"open",
"untaint",
"forms",
"opener",
"valueof",
"frame",
"option",
"window",
"yield",
]

proxies = {
 "http": "http://127.0.0.1:8080",
 "https": "http://127.0.0.1:8080",
}


def getWords(content:str):
    allWords = []
    #print(content)
    content = beautify(content)
    regex_content = re.findall(r'[a-zA-Z0-9_\-\.]+',content,re.I)
    for word in regex_content:
        if '.' in word:
            w = word.split('.')[-1:][0]
            if w and w not in allWords:
                allWords.append(w)
        elif len(word) == 1:
            if word in string.punctuation:
                pass 
            elif word in string.ascii_letters:
                if word not in allWords:
                    allWords.append(word)
            elif word in string.digits:
                pass
        else:
            if word not in allWords:
                allWords.append(word) 
    allWords
    F_allWords = []
    for word_ in allWords:
        if word_.lower() not in blacklisted:
            if word_ not in F_allWords:
                F_allWords.append(word_)
    return F_allWords

def main(jsFile):
    bad = not 1
    path = os.path.abspath("getjswords.py")
    if '/' not in jsFile :
        print('Bad URL: %s'%jsFile,end="")
        print(', please check your url',end="")
        print(', pass..')
        bad = not 0 
    if bad is False:
        try:
            path = sys.argv[1]
            domain = path.split('/')[0]
            print(domain)
            urls = open(path+"alljs."+domain+".txt", "r")
            file = open(path+"/"+"words.txt", "a+")
            for site in urls:
                print(site)
                headers = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:84.0) Gecko/20100101 Firefox/84.0'}
                req = requests.get(site.rstrip(),headers=headers,verify=False)
                content = req.content.decode('utf-8','replace')
                print(req.status_code)
                if (req.status_code == 200):
                    words = getWords(content)
                    for word in words:
                        print(word)
                        file.write(str(word+'\n'))
                    file.close()
                else:
                   print("error")
        except Exception as err:
            sys.exit(print(err))


def usage():
    name = sys.argv[0]
    print(path)
    print('Usage:')
    print('\tpython3 %s https://example.com/javascripts/main.js'%name)
    print('\tcat my_js_files.txt | python3 %s'%name)
    print('\n\tby @m4ll0k - github.com/m4ll0k')
    sys.exit(0)

stdin=False
if len(sys.argv) == 2:
    if sys.argv[1] == '-h':
        usage()
    main(
        sys.argv[1]

    )
else:
    for jsFile in sys.stdin.readlines():
        stdin=True
        jsFile = jsFile.strip()
        print(jsFile)
        if jsFile == '\n':
            usage()
        main(jsFile)

if len(sys.argv) == 1 and stdin is False:
    usage()
