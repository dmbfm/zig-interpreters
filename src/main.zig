const std = @import("std");
const zdf = @import("zdf");

const Args = zdf.Args;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const stdout = std.io.getStdOut().writer();
const stdin = std.io.getStdIn().reader();

const ExprKind = union(enum) {
    Unary: *Expr,
    Binary: BinaryExpr,
    Literal: Token,
    Grouping: *Expr,
};

const UnaryExpr = struct {
    expr: *Expr,
    op: Token,
};

const BinaryExpr = struct {
    left: *Expr,
    right: *Expr,
    op: Token,
};

const Expr = struct {
    kind: ExprKind,

    pub fn unary(expr: *Expr, op: Token) Expr {
        return .{
            .kind = .{ .Unary = .{ .expr = expr, .op = op } },
        };
    }

    pub fn binary(left: *Expr, op: Token, right: *Expr) Expr {
        return .{
            .kind = .{ .Binary = .{ .left = left, .right = right, .op = op } },
        };
    }

    pub fn literal(t: Token) Expr {
        return .{ .kind = .{ .Literal = t } };
    }

    pub fn literalNumber(num: f64) Expr {
        return .{ .kind = .{ .Literal = Token.number(num) } };
    }

    pub fn literalString(str: []const u8) Expr {
        return .{ .kind = .{ .Literal = Token.init(.{ .String = str }, str) } };
    }

    pub fn grouping(expr: *Expr) Expr {
        return .{ .kind = .{ .Grouping = expr } };
    }

    pub fn print(self: Expr, wr: anytype) anyerror!void {
        switch (self.kind) {
            .Unary => |expr| {
                try wr.writeAll("Uniary[");
                try expr.print(wr);
                try wr.writeAll("]");
            },
            .Literal => |token| {
                try token.print(wr);
            },
            .Binary => |binExpr| {
                try wr.print("({s} ", .{binExpr.op.string});
                try binExpr.left.print(wr);
                try wr.writeAll(" ");
                try binExpr.right.print(wr);
                try wr.writeAll(")");
            },
            .Grouping => |expr| {
                try wr.writeAll("( ");
                try expr.print(wr);
                try wr.writeAll(" )");
            },
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

    pub fn scan(self: *Scanner, allocator: *Allocator) ![]Token {
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

const Intepreter = struct {
    allocator: *Allocator,

    pub fn init(allocator: *Allocator) Intepreter {
        return .{
            .allocator = allocator,
        };
    }

    pub fn initKeywords(self: *Intepreter) !void {
        var keywords = std.StringArrayHashMap(TokenKind).init(self.allocator);

        try keywords.put("var", .Var);
        try keywords.put("fun", .Fun);
    }

    pub fn run(self: *Intepreter, source: []const u8) !void {
        var scanner = Scanner.init(source);
        var tokens = try scanner.scan(self.allocator);
        defer self.allocator.free(tokens);

        for (tokens) |token| {
            try stdout.print("'{s}' \t {}\n", .{ token.string, token });
        }
    }

    pub fn runFile(self: *Intepreter, filename: []const u8) !void {
        var file = try std.fs.cwd().openFile(filename, .{});
        var contents = try file.readToEndAlloc(self.allocator, 1073741824);

        return self.run(contents);
    }

    pub fn runRepl(self: *Intepreter) !void {
        var buf: [1024]u8 = undefined;

        while (true) {
            try stdout.writeAll("> ");
            if (try stdin.readUntilDelimiterOrEof(buf[0..], '\n')) |line| {
                if (std.mem.eql(u8, line, "quit")) {
                    break;
                }
                try self.run(line);
            }
        }
    }
};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = &arena.allocator;

    var interpreter = Intepreter.init(allocator);

    var expr = Expr.binary(&Expr.literalNumber(2.0), Token.init(.Star, "*"), &Expr.binary(&Expr.literalNumber(32.34), Token.init(.Plus, "+"),
    // &Expr.literalNumber(2.34),
    &Expr.literalString("hello!")));

    try expr.print(stdout);
    try stdout.writeAll("\n");

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
