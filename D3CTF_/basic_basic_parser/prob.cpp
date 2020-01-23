// g++ prob.cpp -o prob -std=c++11 -O2 -no-pie
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <map>
#include <cstdlib>
#include <string.h>
#include <memory.h>
#include <unistd.h>
#include <sstream>
#include <stdlib.h>
#include <map>
#include <list>
using namespace std;

inline void ERROR_MSG(const char *msg)
{
    cerr << msg << endl;
    exit(-1);
}

class LAnalysis   //lexer 
{
  public:
    enum WordType
    {
        BEGIN = 1,
        END = 2,
        INTEGER = 3,
        IF = 4,
        THEN = 5,
        ELSE = 6,
        FUNCTION = 7,
        READ = 8,
        WRITE = 9,
        SYMBOL = 10,
        CONSTANT = 11,
        EQ = 12,
        NE = 13,
        LE = 14,
        LT = 15,
        BE = 16,
        BT = 17,
        SUB = 18,
        MUL = 19,
        ASSIGN = 20,
        LBRAC = 21,
        RBRAC = 22,
        SEM = 23,
        EOLN = 24,
        MYEOF = 25
    };
    enum ErrorTypr
    {
        OPERA_ERROR = 1,
        SYM_ERROR = 2
    };
    LAnalysis()//构造函数
    {
        initTable(); //往symbols里 加关键字
    }
    LAnalysis(string source)//构造函数
    {
        this->source = source;
        initTable();
    }
    ~LAnalysis()
    {
    }

    void StartAnalysis()
    {
        auto p = this->source.begin();
        string tmp_sym = "";
        while (p != this->source.end())
        {
            if (*p == ' ' || *p == '\n')
            {
                if (tmp_sym.length() == 0)
                {
                    p++;
                    continue;
                }
                if (IsLetterAndNumber(tmp_sym.back()))
                    goto ERROR_SY;
                else
                    goto ERROR_OP;
            }
            if (tmp_sym.length() != 0)
            {
                if (IsLetterAndNumber(*p) && (!IsLetterAndNumber(tmp_sym.back())))
                {
                ERROR_OP:
                    MatchOp(tmp_sym);
                    tmp_sym.clear();
                    goto END;
                   
                }
                if (IsOperator(*p) && (!IsOperator(tmp_sym.back())))
                {
                ERROR_SY:
                    MatchSym(tmp_sym);
                    tmp_sym.clear();
                    goto END;
                }
            }
        END:
            if (*p != ' ' && *p != '\n')
                tmp_sym += *p;
            else if (*p == '\n')
            {
                line++;
                WriteFile("EOLN", EOLN);
            }
            p++;
        }
        if (!IsLetterAndNumber(tmp_sym.back()))
        {
            MatchOp(tmp_sym);
        }
        else
        {
            MatchSym(tmp_sym);
        }
        WriteFile("EOF", MYEOF);
    }

    void DumpOutput(ostream &stream)
    {
        stream << output << endl;
    }

    void DumpError(ostream &stream)
    {
        stream << error << endl;
    }

    void SetSource(string source)
    {
        this->source = source;
    }
    string GetOut()
    {
        return this->output;
    }

  private:
    void MatchOp(string tmp_sym)
    {
        if (!MatchSymbol(tmp_sym))
        {
            for (auto f = tmp_sym.begin(); f != tmp_sym.end();)
            {
                if (isSingleOpera(*f))
                {
                    string tmp = string("") + *f;
                    if (!MatchSymbol(tmp))
                    {
                        WriteError(tmp, OPERA_ERROR);
                    }
                    f++;
                }
                else
                {
                    string tmp = string("") + *f;
                    f++;
                    if (f == tmp_sym.end())
                    {
                        WriteError(tmp, OPERA_ERROR);
                        break;
                    }
                    tmp += *f;
                    if (!MatchSymbol(tmp))
                    {
                        WriteError(tmp, OPERA_ERROR);
                    }
                    f++;
                }
            }
        }
    }

    void MatchSym(string tmp_sym)
    {
        if (!MatchSymbol(tmp_sym))
        {
            if (IsAllNumber(tmp_sym))
            {
                WriteFile(tmp_sym, CONSTANT);
            }
            else
            {
                if (CheckSym(tmp_sym))
                {
                    WriteFile(tmp_sym, SYMBOL);
                }
                else
                {
                    WriteError(tmp_sym, SYM_ERROR);
                }
            }
        }
    }

    bool IsLetterAndNumber(char a)
    {
        return IsLetter(a) | IsNumber(a);
    }

    bool IsLetter(char a)
    {
        if (a >= 'a' && a <= 'z')
        {
            return true;
        }
        if (a >= 'A' && a <= 'Z')
        {
            return true;
        }
        if(a >= 0x7f && a <= 0xff)
        {
            return true;
        }
        return false;
    }
    bool IsNumber(char a)
    {
        if (a >= '0' && a <= '9')
        {
            return true;
        }
        return false;
    }

    bool IsAllNumber(string a)
    {

        for (auto p = a.begin(); p != a.end(); p++)
        {
            if (!IsNumber(*p))
            {
                return false;
            }
        }
        return true;
    }

    bool CheckSym(string sym)
    {
        if (sym.length() == 0)
        {
            return true;
        }
        if (IsNumber(sym[0]))
        {
            return false;
        }
        return true;
    }

    bool MatchSymbol(string sym)//判断给定的字符串是不是Symbol，如果是的话就调用WriteFile
    {
        if (sym.length() == 0)
        {
            return false;
        }
        if (symbol.count(sym))
        {
            WriteFile(sym, symbol[sym]);
            return true;
        }
        return false;
    }

    bool IsOperator(char a)
    {
        if (operatorTable.find(a) != operatorTable.npos)
        {
            return true;
        }
        return false;
    }

    bool isSingleOpera(char a)
    {
        if (singleOpera.find(a) != singleOpera.npos)
        {
            return true;
        }
        return false;
    }

    void WriteFile(string sym, int type)
    {
        output += sym + '\t' + to_string(type) + '\n';
    }

    void WriteError(string err_sym, int type)
    {
        if (type == OPERA_ERROR)
        {
            error += "LINE:" + to_string(line + 1) + "  operat" + err_sym + "error \n";
        }
        if (type == SYM_ERROR)
        {
            error += "LINE:" + to_string(line + 1) + "  identi" + err_sym + "error \n";
        }
    }

    void initTable()
    {
        symbol.insert(pair<string, int>("begin", 1));
        symbol.insert(pair<string, int>("end", 2));
        symbol.insert(pair<string, int>("integer", 3));
        symbol.insert(pair<string, int>("if", 4));
        symbol.insert(pair<string, int>("then", 5));
        symbol.insert(pair<string, int>("else", 6));
        symbol.insert(pair<string, int>("function", 7));
        symbol.insert(pair<string, int>("read", 8));
        symbol.insert(pair<string, int>("write", 9));
        symbol.insert(pair<string, int>("symbol", 10));
        symbol.insert(pair<string, int>("constant", 11));
        symbol.insert(pair<string, int>("=", 12));  // eq
        symbol.insert(pair<string, int>("<>", 13)); // ne
        symbol.insert(pair<string, int>("<=", 14));
        symbol.insert(pair<string, int>("<", 15));
        symbol.insert(pair<string, int>(">=", 16));
        symbol.insert(pair<string, int>(">", 17));
        symbol.insert(pair<string, int>("-", 18));
        symbol.insert(pair<string, int>("*", 19));
        symbol.insert(pair<string, int>(":=", 20));
        symbol.insert(pair<string, int>("(", 21));
        symbol.insert(pair<string, int>(")", 22));
        symbol.insert(pair<string, int>(";", 23));
    }

    map<string, int> symbol;

    string source;
    string output;
    string error;
    string operatorTable = "%&+=-*<>^\\:();";
    string singleOpera = "*();-";

    int line = 0;
};



using namespace std;

enum WordType
{
    BEGIN = 1,
    END = 2,
    INTEGER = 3,
    IF = 4,
    THEN = 5,
    ELSE = 6,
    FUNCTION = 7,
    READ = 8,
    WRITE = 9,
    SYMBOL = 10,
    CONSTANT = 11,
    EQ = 12,
    NE = 13,
    LE = 14,
    LT = 15,
    BE = 16,
    BT = 17,
    SUB = 18,
    MUL = 19,
    ASSIGN = 20,
    LBRAC = 21,
    RBRAC = 22,
    SEM = 23,
    EOLN = 24,
    MYEOF = 25
};


class Variable
{
  public:
    Variable(string name, string process, int tpName, int position) : name(name), process(process), tpName(tpName), position(position)
    {
        //给name_cope分配一块空间，然后将name copy过去
        name_copy = (char*)malloc(name.size());
        memcpy(name_copy,name.c_str(),name.size());
    }
    Variable()
    {

    }
    void Backdoor()
    {
        free(name_copy);
    }

    string GetName()
    {
        return name;
    }
    int GetType()
    {
        return tpName;
    }
    string GetProcess()
    {
        return process;
    }

    int GetPosition()
    {
        return position;
    }

    string Format(int level, string padding)
    {
        string res = padding + "Variable:\n";
        res += padding + "name : " + name + "\n";
        res += padding + "proc : " + process + "\n";
        res += padding + "kind : 0\n";
        if (tpName == FUNCTION)
        {
            res += padding + "type : function\n";
        }
        else if (tpName == INTEGER)
        {
            res += padding + "type : integer\n";
        }
        res += padding + "vlev : " + to_string(level) + "\n";
        res += padding + "vadr : " + to_string(position) + "\n";
        if(name == "backdoor")
        {
            Backdoor();
        }
        return res;
    }

  private:
    string name;
    char* name_copy;
    string process;
    int tpName; // type name
    int position;
};

class Process //作用域
{
  public:
    Process(string name, int level) : processName(name), level(level)  //position没有初始化
    {
        vars = (Variable**)malloc(0x100);
        securt[0] = (char*)malloc(0x10);
        memcpy(securt[0],"d3ctf",6);
    }
    Process()
    {
        vars = (Variable**)malloc(0x100);
        securt[0] = (char*)malloc(0x10);
        memcpy(securt[0],"d3ctf",6);
    }
    void AddVar(Variable a)
    {
        if(position >= 0xe0/8) //设置了最大值，或许可以是负数
        {
            return;
        }
        int n = position++;
        vars[n] = new Variable();
        *vars[n] = a;
    }
    bool HashVar(Variable a)
    {
        return false;
    }
    Variable** GetVar()
    {
        return this->vars;
    }
    int GetNum()
    {
        return this->position;
    }
    string GetName()
    {
        return processName;
    }

    int getLevel()
    {
        return this->level;
    }
    void ClearVar()
    {
        for(int i=0;i<position;i++)
        {
            delete(vars[i]);
            vars[i] = 0;
        }
        position = 0;
    }

    string Format(string padding)
    {
        if (GetName() == "main")
        {
            return "";
        }
        string res = padding + string(securt[0]) +  "Process";
        res += padding + + "\n";
        res += padding + "name : " + GetName() + "\n";
        res += padding + "type : function\n";
        res += padding + "plev : " + to_string(level) + "\n";
        return res;
    }

  private:
    char* securt[4] = {0};    
    Variable** vars;
    string processName;
    int level;
    int position;
};

struct SymInfo
{
    string name;
    int type; // 对应的enum值
};

class Analysis
{
  public:
    Analysis(string data)
    {
        this->source = data;
        string name;
        int t;
        istringstream input(data);
        while (input >> name >> t)
        {
            sourceList.push_back(SymInfo{name, t});
        }
    }
    Analysis()
    {

    }
    ~Analysis()
    {
        for (auto p = allProcess.begin(); p != allProcess.end(); p++)
        {
            delete (*p);
        }
    }
    void Setsource(string source)
    {
        this->source = source;
        string name;
        int t;
        istringstream input(source);
        while (input >> name >> t)
        {
            sourceList.push_back(SymInfo{name, t}); //token list
        }
    }
    void StartAnalysis()
    {
        auto p = sourceList.begin();
        while (p->type == EOLN)
        {
            p++;
            line++;
        }
        nowProcess = new Process("main", 0);
        allProcess.push_back(nowProcess);
        auto next = S(p);
        if (next->type != MYEOF)
        {
            WriteError("can find eof");
        }
    }

    void dumpError(ostream &stream)
    {
        stream << error << endl;
    }

    void dumpVar(ostream &stream)
    {
        for (auto p = allProcess.begin(); p != allProcess.end(); p++)//遍历所有process
        {
            string padding = "";
            
            stream << (*p)->Format(padding);
            auto vars = (*p)->GetVar();
            for (int i = 0; i < (*p)->GetNum(); i++) //遍历当前process的vars
            {
                auto v = vars[i];
                stream << v->Format((*p)->getLevel(), padding);
            }
           
        }
    }

  private:
    void addVar(string name, int type, int NotNext = 0)
    {

        Variable tmpVar = Variable(name, nowProcess->GetName(), type, ++varCount-NotNext);
        varCount -= NotNext;
        nowProcess->AddVar(tmpVar);
    }

    list<SymInfo>::iterator S(list<SymInfo>::iterator p)
    {
        auto next = _get_next(p);
        if (p->type != BEGIN)
        {
            return p;
        }

        next = A(next); // p 指向begin，则next指向begin的下一个token
        auto nnext = _get_next(next);
        if (next->type != SEM)
        {
            WriteError("missing ;");
            nnext = _get_last(nnext);
        }
        next = B(nnext);
        if (next->type != END)
        {
            WriteError("can't find end");
        }
        return _get_next(next);
    }
    list<SymInfo>::iterator A(list<SymInfo>::iterator p)
    {
        return AS(C(p));
    }
    list<SymInfo>::iterator AS(list<SymInfo>::iterator p)
    {
        if (p->type != SEM)
        {
            return p;
        }
        auto p_next = _get_next(p);
        auto next = C(p_next);
        if (next == p_next)
        {
            return _get_last(p_next);
        }
        return AS(next);
    }
    list<SymInfo>::iterator B(list<SymInfo>::iterator p)
    {
        return BS(Z(p));
    }
    list<SymInfo>::iterator BS(list<SymInfo>::iterator p)
    {
        if (p->type != SEM)
        {
            return p;
        }
        p = _get_next(p);
        auto next = Z(p);
        if (next != p)
        {
            next = BS(next);
            return next;
        }
        return p;
    }

    list<SymInfo>::iterator C(list<SymInfo>::iterator p) //
    {
        if (p->type == INTEGER)
        {
            return H(_get_next(p));
        }
        else
        {
            auto backup = p;
            p = _get_next(p);//跳到下一个token
            auto next = H(p);
            if (next == p)
            {
                return _get_last(p);
            }
            if (next->type == SEM)
            {
                WriteError("can't find integer, find " + backup->name);
                return next;
            }
            return _get_last(p);
        }
        return p;
    }
    list<SymInfo>::iterator H(list<SymInfo>::iterator p)
    {
        auto next = I(p);//检查p是否是symbol，如果是symbol，则p++,否则直接返回p
        if (next == p)// p 不是symbol，处理function
        {
            //integer function id()
            if (p->type != FUNCTION)
            {
                return p;
                WriteError("can't find function");
                p = _get_last(p);
            }
            p = _get_next(p);//跳过function
            next = I(p);//则next现在指向 函数名称 的下一个token
            addVar(p->name, FUNCTION);

            auto nnext = _get_next(next);
            if (next->type != LBRAC)//next指向 '('
            {
                WriteError("missing (");
                nnext = _get_last(nnext);
            }
            next = I(nnext);
            if (next->type != RBRAC)
            {
                WriteError("missing )");
                next = _get_last(next);
            }
            nnext = _get_next(next);
            if (nnext->type != SEM)
            {
                WriteError("missing ;");
                nnext = _get_last(nnext);
            }
            lastProcess = nowProcess;
            nowProcess = new Process(p->name, lastProcess->getLevel() + 1);//创建一个新的process
            allProcess.push_back(nowProcess);//压入vector中
            addVar(p->name, FUNCTION, 1);//新增一个变量，类型是function
            auto ret = S(_get_next(nnext));
            if(ret == _get_next(nnext))//没有找到begin
            {
                delete(nowProcess); 
                nowProcess = lastProcess;
                return nnext;//指向 分号
            }
            nowProcess = lastProcess;
            return ret;
        }
        if(next->type == SEM)
        {
            addVar(p->name, INTEGER);
        }
        
        return next;
    }
    list<SymInfo>::iterator I(list<SymInfo>::iterator p)
    {
        if (p->type == SYMBOL)
        {
            return _get_next(p);
        }
        return p;
    }

    list<SymInfo>::iterator IS(list<SymInfo>::iterator p)
    {
        auto next = p;
        return IS(next);
    }

    list<SymInfo>::iterator J(list<SymInfo>::iterator p)
    {
        return JS(X(p));
    }

    list<SymInfo>::iterator JS(list<SymInfo>::iterator p)
    {
        if (p->type == SUB)
        {
            auto next = _get_next(p);
            return JS(X(next));
        }
        return p;
    }

    list<SymInfo>::iterator X(list<SymInfo>::iterator p)
    {
        return XS(Y(p));
    }

    list<SymInfo>::iterator XS(list<SymInfo>::iterator p)
    {
        auto next = Y(p);
        if (next == p)
        {
            if (next->type != MUL)
            {
                return next;
            }
            next = Y(_get_next(p));
            if (next == p)
            {
                return p;
            }
            return XS(next);
        }
        return p;
    }

    list<SymInfo>::iterator P(list<SymInfo>::iterator p)
    {
        if (p->type <= BT && p->type >= EQ)
        {
            return _get_next(p);
        }
        return p;
    }

    list<SymInfo>::iterator K(list<SymInfo>::iterator p)
    {
        return J(P(J(p)));
    }

    list<SymInfo>::iterator Y(list<SymInfo>::iterator p)
    {
        auto next = I(p);
        if (p != next || p->type == LBRAC)
        {
            if (next->type == LBRAC)
            {
                next = _get_next(next);
                CheckVar(p->name, FUNCTION);
                next = J(next);
                if (next->type != RBRAC)
                {
                    WriteError("missing )");
                    next = _get_last(next);
                }
                return _get_next(next);
            }
            CheckVar(p->name, INTEGER);
            return next;
        }
        if (next->type == CONSTANT)
        {
            return _get_next(p);
        }


        return p;
    }

    list<SymInfo>::iterator Z(list<SymInfo>::iterator p)
    {
        if (p->type == READ)
        {
            p = _get_next(p);
            auto nnext = _get_next(p);
            if (p->type != LBRAC)
            {
                nnext = _get_last(nnext);
                WriteError("missing (");
            }
            auto next = I(nnext);
            CheckVar(nnext->name, INTEGER);
            nnext = _get_next(next);
            if (next->type != RBRAC)
            {
                nnext = _get_last(nnext);
                WriteError("missing )");
            }
            return nnext;
        }
        if (p->type == WRITE)
        {
            p = _get_next(p);
            if (p->type != LBRAC)
            {
                p = _get_last(p);
                WriteError("missing (");
            }
            auto next = I(_get_next(p));
            CheckVar(p->name, INTEGER);
            if (next->type != RBRAC)
            {
                next = _get_last(next);
                WriteError("missing )");
            }
            return _get_next(next);
        }
        auto next = I(p);
        if (next != p)
        {
            CheckVar(p->name, INTEGER);
            if (next->type != ASSIGN)
            {

                next = _get_last(next);
            }
            return J(_get_next(next)); 
        }
        if (p->type == IF)
        {
            p = _get_next(p);
            next = K(p);

            if (next->type != THEN)
            {
                WriteError("missing then,find " + next->name);
            }
            next = Z(_get_next(next));

            if (next->type != ELSE)
            {
                WriteError("can't find else,find "+next->name);
            }
            next = Z(_get_next(next));
            return next;
        }
        return p;
    }

    list<SymInfo>::iterator _get_next(list<SymInfo>::iterator p)
    {
        p++;
        while (p->type == EOLN)
        {
            p++;
            line++;
        }
        return p;
    }
    list<SymInfo>::iterator _get_last(list<SymInfo>::iterator p)
    {
        p--;
        while (p->type == EOLN)
        {
            p--;
            line--;
        }
        return p;
    }

    void WriteFile(string msg)
    {
    }

    void WriteError(string msg)
    {
        error += "LINE:    " + to_string(line) + "    " + msg + "\n";
    }

    void CheckVar(string varName, int type)
    {
        if (!IsLetterAndNumber(varName[0]))
        {
            return;
        }
        if (nowProcess->HashVar(Variable(varName, nowProcess->GetName(), type, 0)))
        {
            return;
        }
        WriteError("undefined var " + varName);
    }
    bool IsLetterAndNumber(char a)
    {
        return IsLetter(a) | IsNumber(a);
    }

    bool IsLetter(char a)
    {
        if (a >= 'a' && a <= 'z')
        {
            return true;
        }
        if (a >= 'A' && a <= 'Z')
        {
            return true;
        }
        return false;
    }
    bool IsNumber(char a)
    {
        if (a >= '0' && a <= '9')
        {
            return true;
        }
        return false;
    }
    Process *nowProcess;
    Process *lastProcess;
    list<Process *> allProcess;
    list<SymInfo> sourceList;
    string error;
    string sym;
    string source;
    int line = 1;
    int varCount = 0;
};


int main(int argc, char **argv)
{
    setbuf(stdin,NULL);
    setbuf(stdout,NULL);
    setbuf(stdout,NULL);
    string line,data;
    
    while (1)
    {
        LAnalysis* analysiser = new LAnalysis();
        Analysis* anlysisor = new Analysis();
        cout << ">";
        cin >> line;
        if(line != "OVER")
        {
            data += line + "\n";
            continue;
        }
        analysiser->SetSource(data);
        analysiser->StartAnalysis();
        string data2 =  analysiser->GetOut();
        anlysisor->Setsource(data2);
        anlysisor->StartAnalysis();
        cout<<"leave comment for this submit"<<endl;
        cout<<"size:"<<endl;
        unsigned int nnn;
        cin >> nnn;
        getchar();
        char* comment = 0;
        if(nnn < 0x200)
        {
            comment = (char*)malloc(nnn);
            cout << "comment:";
            read(0,comment,nnn);
        }
        cout << "thanks for support , if you find some bugs , please ignore it :P" << endl;
        
        anlysisor->dumpError(cerr);
        anlysisor->dumpVar(cout);
        data = "";
        
        cout << "continue ? " << endl;
        cin >> line;
        if(line == "NO")
        {
            if(comment)
                free(comment);
            return 0;
        }
    }
    return 0;

}
