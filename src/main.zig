const std = @import("std");
const zdf = @import("zdf");

const Args = zdf.Args;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const stdout = std.io.getStdOut().writer();
const stdin = std.io.getStdIn().reader();

pub const log_level: std.log.Level = .info;
// pub const log_level: std.log.Level = .warn;

// Grammar:
//
//
// program              ::= statement* EOF ;
// statement            ::= expression_statement | print_statement ;
// expression_statement ::= expression ";"
// print_statement      ::= "print" expression ";"
//
// expression           ::= equality ;
// equality             ::= comparison (("==" | "!=") comparison)* ;
// comparison           ::= term (("<" | ">" | "<=" | ">=") term)* ;
// term                 ::= factor (("+" | "-") factor)* ;
// factor               ::= unary (("*" | "\") unary)* ;
// unary                ::= ("!", "-") unary | primary ;
// primary              ::= number | string | boolean | "nil" | "(" expression ")" ;
// number               ::= {insert some number regex here}
// string               ::= """ [character]* """ ;
// boolean              ::= "true" | "false" ;
//

const ExprKind = union(enum) {
    add: BinaryExpr,
    sub: BinaryExpr,
    mul: BinaryExpr,
    div: BinaryExpr,

    eq: BinaryExpr,
    neq: BinaryExpr,

    lt: BinaryExpr,
    st: BinaryExpr,
    let: BinaryExpr,
    set: BinaryExpr,

    not: *Expr,
    minus: *Expr,
    unknown: void,
    err: void,

    num: f64,
    boolean: bool,
    nil: void,
    string: []const u8,
};

const BinaryExpr = struct {
    left: *Expr,
    right: *Expr,
};

const RuntimeError = error{
    TypeError,
    NotImplemented,
    OutOfMemory,
};

const Result = union(enum) {
    num: f64,
    boolean: bool,
    string: []const u8,

    pub fn num(val: f64) Result {
        return .{ .num = val };
    }

    pub fn boolean(val: bool) Result {
        return .{ .boolean = val };
    }

    pub fn string(val: []const u8) Result {
        return .{ .string = val };
    }

    pub fn expect(self: *Result, kind: std.meta.Tag(Result)) RuntimeError!*Result {
        if (@enumToInt(self.*) != @enumToInt(kind)) {
            return RuntimeError.TypeError;
        }

        return self;
    }

    pub fn print(self: Result, wr: anytype) !void {
        switch (self) {
            .num => |v| {
                try wr.print("{}", .{v});
            },
            .boolean => |v| {
                try wr.print("{}", .{v});
            },
            .string => |v| {
                try wr.print("\"{s}\"", .{v});
            },
        }
    }
};

const Stmt = union(enum) {
    PrintStmt: *Expr,
    ExprStmt: *Expr,
};

const Expr = struct {
    kind: ExprKind,

    pub fn init(kind: ExprKind) Expr {
        return .{ .kind = kind };
    }

    pub fn add(left: *Expr, right: *Expr) Expr {
        return .{ .kind = .{ .add = .{ .left = left, .right = right } } };
    }

    pub fn sub(left: *Expr, right: *Expr) Expr {
        return .{ .kind = .{ .sub = .{ .left = left, .right = right } } };
    }

    pub fn mul(left: *Expr, right: *Expr) Expr {
        return .{ .kind = .{ .mul = .{ .left = left, .right = right } } };
    }

    pub fn div(left: *Expr, right: *Expr) Expr {
        return .{ .kind = .{ .div = .{ .left = left, .right = right } } };
    }

    pub fn eq(left: *Expr, right: *Expr) Expr {
        return .{ .kind = .{ .eq = .{ .left = left, .right = right } } };
    }

    pub fn neq(left: *Expr, right: *Expr) Expr {
        return .{ .kind = .{ .neq = .{ .left = left, .right = right } } };
    }

    pub fn lt(left: *Expr, right: *Expr) Expr {
        return .{ .kind = .{ .lt = .{ .left = left, .right = right } } };
    }

    pub fn let(left: *Expr, right: *Expr) Expr {
        return .{ .kind = .{ .let = .{ .left = left, .right = right } } };
    }

    pub fn st(left: *Expr, right: *Expr) Expr {
        return .{ .kind = .{ .st = .{ .left = left, .right = right } } };
    }

    pub fn set(left: *Expr, right: *Expr) Expr {
        return .{ .kind = .{ .set = .{ .left = left, .right = right } } };
    }

    pub fn not(e: *Expr) Expr {
        return .{ .kind = .{ .not = e } };
    }

    pub fn minus(e: *Expr) Expr {
        return .{ .kind = .{ .minus = e } };
    }

    pub fn num(v: f64) Expr {
        return .{ .kind = .{ .num = v } };
    }

    pub fn boolean(v: bool) Expr {
        return .{ .kind = .{ .boolean = v } };
    }

    pub fn nil() Expr {
        return .{ .kind = .nil };
    }

    pub fn err() Expr {
        return .{ .kind = .err };
    }

    pub fn string(val: []const u8) Expr {
        return .{ .kind = .{ .string = val } };
    }

    fn printBinary(op: []const u8, b: *const BinaryExpr, wr: anytype) !void {
        try wr.print("({s} ", .{op});
        try b.left.print(wr);
        try wr.writeAll(" ");
        try b.right.print(wr);
        try wr.writeAll(")");
    }

    fn printUnary(op: []const u8, e: *const Expr, wr: anytype) !void {
        try wr.print("({s} ", .{op});
        try e.print(wr);
        try wr.writeAll(")");
    }

    pub fn print(self: Expr, wr: anytype) anyerror!void {
        switch (self.kind) {
            .add => |*v| {
                try printBinary("+", v, wr);
            },
            .sub => |*v| {
                try printBinary("-", v, wr);
            },
            .mul => |*v| {
                try printBinary("*", v, wr);
            },
            .div => |*v| {
                try printBinary("/", v, wr);
            },
            .eq => |*v| {
                try printBinary("==", v, wr);
            },
            .neq => |*v| {
                try printBinary("!=", v, wr);
            },
            .lt => |*v| {
                try printBinary(">", v, wr);
            },
            .st => |*v| {
                try printBinary("<", v, wr);
            },
            .let => |*v| {
                try printBinary(">=", v, wr);
            },
            .set => |*v| {
                try printBinary("<=", v, wr);
            },
            .not => |e| {
                try printUnary("!", e, wr);
            },
            .minus => |e| {
                try printUnary("-", e, wr);
            },
            .num => |v| {
                try wr.print("{}", .{v});
            },
            .err => {
                try wr.print("Error", .{});
            },
            .boolean => |v| {
                try wr.writeAll(if (v) "true" else "false");
            },
            .string => |v| {
                try wr.print("\"{s}\"", .{v});
            },
            .nil => {
                try wr.writeAll("nil");
            },
            else => {},
        }
    }
};

const TokenError = enum {
    StringNotClosed,
    NumberError,
};

const TokenKind = union(enum) {
    LeftParen: void,
    RightParen: void,
    LeftBrace: void,
    RightBrace: void,
    Comma: void,
    Dot: void,
    Minus: void,
    Plus: void,
    Semicolon: void,
    Slash: void,
    Star: void,
    Bang: void,
    BangEqual: void,
    Equal: void,
    EqualEqual: void,
    Greater: void,
    GreaterEqual: void,
    Less: void,
    LessEqual: void,
    Identifier: void,
    String: []const u8,
    Number: f64,
    And: void,
    Or: void,
    If: void,
    Else: void,
    Var: void,
    Fun: void,
    True: void,
    False: void,
    While: void,
    Return: void,
    Print: void,
    Nil: void,
    For: void,
    Eof: void,
    Unknown: void,
    Error: TokenError,
};

const KeywordMap = std.ComptimeStringMap(TokenKind, .{
    .{ "and", .And },
    .{ "or", .Or },
    .{ "if", .If },
    .{ "else", .Else },
    .{ "fun", .Fun },
    .{ "true", .True },
    .{ "false", .False },
    .{ "while", .While },
    .{ "return", .Return },
    .{ "print", .Print },
    .{ "nil", .Nil },
    .{ "for", .For },
    .{ "var", .Var },
});

const Token = struct {
    string: []const u8,
    line: usize,
    kind: TokenKind,

    pub fn init(kind: TokenKind, string: []const u8) Token {
        return .{
            .kind = kind,
            .string = string,
            .line = 0,
        };
    }

    pub fn initWithLine(kind: TokenKind, string: []const u8, line: usize) Token {
        return .{
            .kind = kind,
            .string = string,
            .line = line,
        };
    }

    pub fn number(num: f64) Token {
        return .{ .string = "", .line = 0, .kind = .{ .Number = num } };
    }

    pub fn print(self: Token, wr: anytype) anyerror!void {
        switch (self.kind) {
            .Number => |num| {
                try wr.print("{}", .{num});
            },
            .String => |str| {
                try wr.print("\"{s}\"", .{str});
            },
            else => {
                try wr.print("{s}", .{self.string});
            },
        }
    }
};

const Scanner = struct {
    buffer: []const u8,
    cur: usize = 0,
    start: usize = 0,
    line: usize = 1,

    pub fn init(buffer: []const u8) Scanner {
        return .{
            .buffer = buffer,
        };
    }

    pub fn scan(self: *Scanner, allocator: Allocator) ![]Token {
        var tokens = std.ArrayList(Token).init(allocator);
        defer tokens.deinit();

        while (self.nextToken()) |t| {
            self.start = self.cur;
            try tokens.append(t);
        }

        return tokens.toOwnedSlice();
    }

    pub fn token(self: Scanner, kind: TokenKind) Token {
        return Token{ .line = self.line, .string = self.buffer[self.start..self.cur], .kind = kind };
    }

    pub fn nextToken(self: *Scanner) ?Token {
        while (self.eat()) |ch| {
            switch (ch) {
                '*' => return self.token(.Star),
                '(' => return self.token(.LeftParen),
                ')' => return self.token(.RightParen),
                '{' => return self.token(.LeftBrace),
                '}' => return self.token(.RightBrace),
                ',' => return self.token(.Comma),
                '.' => return self.token(.Dot),
                ';' => return self.token(.Semicolon),
                '+' => return self.token(.Plus),
                '-' => return self.token(.Minus),
                '=' => {
                    if (self.match('=')) {
                        return self.token(.EqualEqual);
                    } else {
                        return self.token(.Equal);
                    }
                },
                '!' => {
                    if (self.match('=')) {
                        return self.token(.BangEqual);
                    } else {
                        return self.token(.Bang);
                    }
                },
                '<' => {
                    if (self.match('=')) {
                        return self.token(.LessEqual);
                    } else {
                        return self.token(.Less);
                    }
                },
                '>' => {
                    if (self.match('=')) {
                        return self.token(.GreaterEqual);
                    } else {
                        return self.token(.Greater);
                    }
                },
                '/' => {
                    if (self.match('/')) {
                        while (self.peek()) |_ch| {
                            if (_ch == '\n') break;
                            _ = self.eat();
                        }
                    } else {
                        return self.token(.Slash);
                    }
                },
                ' ', '\t', '\r' => {
                    self.start = self.cur;
                },
                '\n' => {
                    self.start = self.cur;
                    self.line += 1;
                },
                '"' => {
                    var stringStart = self.cur;
                    var stringEnd: usize = stringStart;
                    while (self.eat()) |_ch| {
                        if (_ch == '"') {
                            stringEnd = self.cur - 1;
                            break;
                        }
                    } else {
                        return self.token(TokenKind{ .Error = .StringNotClosed });
                    }

                    return self.token(TokenKind{ .String = self.buffer[stringStart..stringEnd] });
                },
                '0'...'9' => {
                    var numStart = self.cur - 1;
                    var numEnd = numStart;

                    while (self.peek()) |_ch| {
                        switch (_ch) {
                            '0'...'9', '.' => {
                                _ = self.eat();
                                numEnd += 1;
                            },
                            else => {
                                break;
                            },
                        }
                    }

                    var num = std.fmt.parseFloat(f64, self.buffer[numStart .. numEnd + 1]) catch {
                        return self.token(.{ .Error = .NumberError });
                    };

                    return self.token(.{ .Number = num });
                },
                'a'...'z', 'A'...'Z', '_' => {
                    while (self.peek()) |_ch| {
                        switch (_ch) {
                            'a'...'z', 'A'...'Z', '0'...'9', '_' => {
                                _ = self.eat();
                            },
                            else => {
                                break;
                            },
                        }
                    }

                    var name = self.buffer[self.start..self.cur];

                    if (KeywordMap.get(name)) |tk| {
                        return self.token(tk);
                    }

                    return self.token(.Identifier);
                },
                else => return self.token(.Unknown),
            }
        }

        return null;
    }

    pub fn eof(self: Scanner) bool {
        return self.cur >= self.buffer.len;
    }

    pub fn match(self: *Scanner, ch: u8) bool {
        if (!self.eof() and self.buffer[self.cur] == ch) {
            self.cur += 1;
            return true;
        }

        return false;
    }

    pub fn peek(self: *Scanner) ?u8 {
        if (self.eof()) {
            return null;
        }

        return self.buffer[self.cur];
    }

    pub fn eat(self: *Scanner) ?u8 {
        if (self.cur >= self.buffer.len) {
            return null;
        }

        defer self.cur += 1;
        return self.buffer[self.cur];
    }
};

const Parser = struct {
    tokens: []Token,
    cur: usize = 0,
    arena: std.heap.ArenaAllocator,
    allocator: Allocator,

    pub fn init(tokens: []Token, allocator: Allocator) Parser {
        return .{
            .tokens = tokens,
            .allocator = allocator,
            .arena = std.heap.ArenaAllocator.init(allocator),
        };
    }

    pub fn deinit(self: *Parser) void {
        self.arena.deinit();
    }

    pub fn createExpr(self: *Parser) Allocator.Error!*Expr {
        return self.arena.allocator().create(Expr);
    }

    pub fn createExprWithKind(self: *Parser, kind: ExprKind) !*Expr {
        var expr = try self.createExpr();
        expr.kind = kind;

        return expr;
    }

    pub fn nextToken(self: *Parser) ?Token {
        if (self.cur >= self.tokens.len) {
            return null;
        }

        defer self.cur += 1;
        return self.tokens[self.cur];
    }

    pub fn match(self: *Parser, kind: TokenKind) ?Token {
        if (self.cur >= self.tokens.len or @enumToInt(self.tokens[self.cur].kind) != @enumToInt(kind)) {
            return null;
        }

        defer self.cur += 1;
        return self.tokens[self.cur];
    }

    pub fn matchOneOf(self: *Parser, kinds: []const TokenKind) ?Token {
        for (kinds) |kind| {
            if (self.match(kind)) |token| {
                return token;
            }
        }

        return null;
    }

    pub fn expect(self: *Parser, kind: TokenKind) !Token {
        if (self.nextToken()) |token| {
            if (@enumToInt(token.kind) != @enumToInt(kind)) {
                return error.WrongTokenKind;
            } else {
                return token;
            }
        } else {
            return error.NoToken;
        }
    }

    pub fn parseExpr(self: *Parser) !*Expr {
        if (self.tokens.len == 0) {
            var e = try self.createExprWithKind(.err);
            return e;
        }

        return self.parseEquality();
    }

    pub fn parseEquality(self: *Parser) !*Expr {
        var current = try self.parseComp();

        while (self.matchOneOf(&[_]TokenKind{ .EqualEqual, .BangEqual })) |token| {
            var right = try self.parseComp();
            var previous = current;
            current = try self.createExpr();
            current.* = switch (token.kind) {
                .EqualEqual => Expr.eq(previous, right),
                .BangEqual => Expr.neq(previous, right),
                else => unreachable,
            };
        }

        return current;
    }

    pub fn parseComp(self: *Parser) !*Expr {
        var current = try self.parseTerm();

        var ops = [_]TokenKind{ .Less, .LessEqual, .Greater, .GreaterEqual };

        while (self.matchOneOf(&ops)) |token| {
            var right = try self.parseTerm();

            var previous = current;

            current = try self.createExpr();
            current.* = switch (token.kind) {
                .Less => Expr.st(previous, right),
                .LessEqual => Expr.set(previous, right),
                .Greater => Expr.lt(previous, right),
                .GreaterEqual => Expr.let(previous, right),
                else => unreachable,
            };
        }

        return current;
    }

    pub fn parseTerm(self: *Parser) !*Expr {
        var current = try self.parseFact();

        var ops = [_]TokenKind{ .Plus, .Minus };

        while (self.matchOneOf(&ops)) |token| {
            var right = try self.parseFact();
            var previous = current;
            current = try self.createExpr();
            current.* = switch (token.kind) {
                .Plus => Expr.add(previous, right),
                .Minus => Expr.sub(previous, right),
                else => unreachable,
            };
        }

        return current;
    }

    pub fn parseFact(self: *Parser) !*Expr {
        var current = try self.parseUnary();

        var ops = [_]TokenKind{ .Star, .Slash };

        while (self.matchOneOf(&ops)) |token| {
            var right = try self.parseUnary();
            var previous = current;
            current = try self.createExpr();
            current.* = switch (token.kind) {
                .Star => Expr.mul(previous, right),
                .Slash => Expr.div(previous, right),
                else => unreachable,
            };
        }

        return current;
    }

    pub fn parseUnary(self: *Parser) anyerror!*Expr {
        var ops = [_]TokenKind{ .Bang, .Minus };

        if (self.matchOneOf(&ops)) |token| {
            var e = try self.createExpr();
            e.* = switch (token.kind) {
                .Bang => Expr.not(try self.parseUnary()),
                .Minus => Expr.minus(try self.parseUnary()),
                else => unreachable,
            };

            return e;
        }

        return try self.parsePrimary();
    }

    // Number | string | "true" | "false" | "nil"
    pub fn parsePrimary(self: *Parser) !*Expr {
        var e = try self.createExpr();

        if (self.nextToken()) |token| {
            e.* = switch (token.kind) {
                .Number => |v| Expr.num(v),
                .True => Expr.boolean(true),
                .False => Expr.boolean(false),
                .Nil => Expr.nil(),
                .LeftParen => blk: {
                    var exp = try self.parseExpr();
                    _ = self.expect(.RightParen) catch return error.ParenthesisNotClosed;
                    break :blk exp.*;
                },
                .String => |v| Expr.string(v),
                else => Expr.err(),
            };
        }

        return e;
    }
};

const Intepreter = struct {
    arena: std.heap.ArenaAllocator,

    pub fn init(allocator: Allocator) Intepreter {
        return .{
            .arena = std.heap.ArenaAllocator.init(allocator),
        };
    }

    pub fn deinit(self: *Intepreter) void {
        self.arena.deinit();
    }

    pub fn stringConcat(self: *Intepreter, s1: []const u8, s2: []const u8) ![]const u8 {
        var newString = self.arena.allocator().alloc(u8, s1.len + s2.len) catch return RuntimeError.OutOfMemory;

        std.mem.copy(u8, newString, s1);
        std.mem.copy(u8, newString[s1.len..], s2);

        return newString;
    }

    pub fn evalAdd(self: *Intepreter, binExpr: BinaryExpr) RuntimeError!Result {
        var left = try self.eval(binExpr.left);
        var right = try self.eval(binExpr.right);

        if (@enumToInt(left) != @enumToInt(right)) {
            return RuntimeError.TypeError;
        }

        return switch (left) {
            .num => |v| Result.num(v + right.num),
            .string => |v| Result.string(try self.stringConcat(v, right.string)),
            else => RuntimeError.TypeError,
        };
    }

    pub fn evalEq(self: *Intepreter, expr: BinaryExpr) RuntimeError!Result {
        var left = try self.eval(expr.left);
        var right = try self.eval(expr.right);

        if (@enumToInt(left) != @enumToInt(right)) {
            return RuntimeError.TypeError;
        }

        return switch (left) {
            .num => |v| Result.boolean(v == right.num),
            .string => |v| Result.boolean(std.mem.eql(u8, v, right.string)),
            .boolean => |v| Result.boolean(v == right.boolean),
        };
    }

    pub fn evalNeq(self: *Intepreter, expr: BinaryExpr) RuntimeError!Result {
        var left = try self.eval(expr.left);
        var right = try self.eval(expr.right);

        if (@enumToInt(left) != @enumToInt(right)) {
            return RuntimeError.TypeError;
        }

        return switch (left) {
            .num => |v| Result.boolean(v != right.num),
            .string => |v| Result.boolean(!std.mem.eql(u8, v, right.string)),
            .boolean => |v| Result.boolean(v != right.boolean),
        };
    }
    pub fn eval(self: *Intepreter, expr: *Expr) RuntimeError!Result {
        return switch (expr.kind) {
            .add => |v| try self.evalAdd(v),
            .sub => |v| Result.num((try (try self.eval(v.left)).expect(.num)).num - (try (try self.eval(v.right)).expect(.num)).num),
            .mul => |v| Result.num((try (try self.eval(v.left)).expect(.num)).num * (try (try self.eval(v.right)).expect(.num)).num),
            .div => |v| Result.num((try (try self.eval(v.left)).expect(.num)).num / (try (try self.eval(v.right)).expect(.num)).num),
            .eq => |v| try self.evalEq(v),
            .neq => |v| try self.evalNeq(v),
            .st => |v| Result.boolean((try (try self.eval(v.left)).expect(.num)).num < (try (try self.eval(v.right)).expect(.num)).num),
            .set => |v| Result.boolean((try (try self.eval(v.left)).expect(.num)).num <= (try (try self.eval(v.right)).expect(.num)).num),
            .lt => |v| Result.boolean((try (try self.eval(v.left)).expect(.num)).num > (try (try self.eval(v.right)).expect(.num)).num),
            .let => |v| Result.boolean((try (try self.eval(v.left)).expect(.num)).num >= (try (try self.eval(v.right)).expect(.num)).num),
            .minus => |v| Result.num(-(try (try self.eval(v)).expect(.num)).num),
            .not => |v| Result.boolean(!(try (try self.eval(v)).expect(.boolean)).boolean),
            .num => |v| Result.num(v),
            .boolean => |v| Result.boolean(v),
            .string => |v| Result.string(v),
            else => RuntimeError.NotImplemented,
        };
    }

    pub fn run(self: *Intepreter, source: []const u8) !void {
        var scanner = Scanner.init(source);
        var allocator = self.arena.allocator();
        var tokens = try scanner.scan(allocator);
        var parser = Parser.init(tokens, allocator);
        defer parser.deinit();
        defer allocator.free(tokens);

        std.log.info("{a}", .{tokens});

        var e = try parser.parseExpr();
        try e.print(stdout);
        try stdout.writeAll("\n");

        if (self.eval(e)) |value| {
            try value.print(stdout);
            try stdout.writeAll("\n");
        } else |err| {
            try stdout.print("RuntimeError: {}\n", .{err});
        }
    }

    pub fn runFile(self: *Intepreter, filename: []const u8) !void {
        var file = try std.fs.cwd().openFile(filename, .{});
        var contents = try file.readToEndAlloc(self.arena.allocator(), 1073741824);

        return self.run(contents);
    }

    pub fn runRepl(self: *Intepreter) !void {
        var buf: [1024]u8 = undefined;

        while (true) {
            try stdout.writeAll("\n> ");
            if (try stdin.readUntilDelimiterOrEof(buf[0..], '\n')) |line| {
                if (std.mem.eql(u8, line, "quit")) {
                    break;
                }
                self.run(line) catch |e| {
                    try stdout.print("Error: {}\n", .{e});
                };
            }
        }
    }
};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var interpreter = Intepreter.init(allocator);
    var args = try Args.init(allocator);

    if (args.argc < 2) {
        try interpreter.runRepl();
    } else {
        var filename = args.argv[1];
        try interpreter.runFile(filename);
    }
}

const test_allocator = std.testing.allocator;
const expect = std.testing.expect;

test "Scanner 1" {
    var string = "var myvar = 20;";
    var scanner = Scanner.init(string);
    const tokens = try scanner.scan(test_allocator);
    defer test_allocator.free(tokens);

    try expect(tokens.len == 5);
    try expect(tokens[0].kind == .Var);
    try expect(tokens[1].kind == .Identifier);
    try expect(tokens[2].kind == .Equal);
    try expect(tokens[3].kind == .Number);
    try expect(tokens[4].kind == .Semicolon);
}

test "Scanner 2" {
    var string = "fun foo(x) { return x; }";
    var scanner = Scanner.init(string);
    const tokens = try scanner.scan(test_allocator);
    defer test_allocator.free(tokens);

    try expect(tokens.len == 10);
    try expect(tokens[0].kind == .Fun);
    try expect(tokens[1].kind == .Identifier);
    try expect(tokens[2].kind == .LeftParen);
    try expect(tokens[3].kind == .Identifier);
    try expect(tokens[4].kind == .RightParen);
    try expect(tokens[5].kind == .LeftBrace);
    try expect(tokens[6].kind == .Return);
    try expect(tokens[7].kind == .Identifier);
    try expect(tokens[8].kind == .Semicolon);
    try expect(tokens[9].kind == .RightBrace);
}
