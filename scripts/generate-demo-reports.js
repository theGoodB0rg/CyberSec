const fs = require('fs');
const path = require('path');

const BASE_OUTPUT_DIR = path.join(__dirname, '..', 'server', 'sample-reports');
const HEADER = 'Target URL,Place,Parameter,Technique(s),Note(s)';
const NOTE_SUFFIXES = [
  'Confidence derived from 3/3 positive payloads.',
  'Retest with tamper scripts confirmed consistent delays.',
  'Manual verification reproduced the SQL error messages.',
  'Heuristic fingerprint matched historical injection behaviour.',
  'WAF bypass payload served identical result sets.',
  'Automated rerun validated exploit stability at 95% confidence.'
];

const hostCatalog = [
  {
    hostname: 'testphp.vulnweb.com',
    runs: 5,
    records: [
      {
        targetUrl: 'https://testphp.vulnweb.com/listproducts.php?cat=1',
        place: 'GET',
        parameter: 'cat',
        technique: 'Boolean-based blind SQL injection',
        note: 'Injected boolean tautology toggled catalogue listing without cache hits.'
      },
      {
        targetUrl: 'https://testphp.vulnweb.com/search.php',
        place: 'POST',
        parameter: 'searchFor',
        technique: 'Time-based blind SQL injection',
        note: 'Payload enforced SLEEP(5) delays while baseline remained <500ms.'
      },
      {
        targetUrl: 'https://testphp.vulnweb.com/userinfo.php',
        place: 'GET',
        parameter: 'id',
        technique: 'Error-based SQL injection',
        note: 'Verbose MySQL error disclosed table structure on malformed UNION payload.'
      },
      {
        targetUrl: 'https://testphp.vulnweb.com/guestbook.php',
        place: 'POST',
        parameter: 'message',
        technique: 'Union query SQL injection',
        note: 'UNION-based exfiltration returned administrator password hashes.'
      }
    ]
  },
  {
    hostname: 'testasp.vulnweb.com',
    runs: 5,
    records: [
      {
        targetUrl: 'https://testasp.vulnweb.com/default.aspx?id=2',
        place: 'GET',
        parameter: 'id',
        technique: 'Boolean-based blind SQL injection',
        note: 'Injected condition modified ASP.NET viewstate output predictably.'
      },
      {
        targetUrl: 'https://testasp.vulnweb.com/search.aspx',
        place: 'POST',
        parameter: 'txtSearch',
        technique: 'Time-based blind SQL injection',
        note: 'WAITFOR DELAY payload introduced 4.5 second average latency.'
      },
      {
        targetUrl: 'https://testasp.vulnweb.com/cart.aspx',
        place: 'GET',
        parameter: 'cartID',
        technique: 'Stacked queries',
        note: 'Stacked INSERT payload succeeded, confirming multi-statement execution.'
      },
      {
        targetUrl: 'https://testasp.vulnweb.com/feedback.aspx',
        place: 'POST',
        parameter: 'txtMessage',
        technique: 'Union query SQL injection',
        note: 'UNION SELECT returned additional columns beyond expected schema.'
      }
    ]
  },
  {
    hostname: 'demo.testfire.net',
    runs: 5,
    records: [
      {
        targetUrl: 'https://demo.testfire.net/bank/login.aspx',
        place: 'POST',
        parameter: 'uid',
        technique: 'Boolean-based blind SQL injection',
        note: 'Account enumeration responded differently to OR-based predicates.'
      },
      {
        targetUrl: 'https://demo.testfire.net/bank/search.aspx',
        place: 'GET',
        parameter: 'query',
        technique: 'Union query SQL injection',
        note: 'UNION payload exposed account table with matching column count.'
      },
      {
        targetUrl: 'https://demo.testfire.net/bank/account.aspx',
        place: 'GET',
        parameter: 'id',
        technique: 'Error-based SQL injection',
        note: 'Server echoed JDBC error revealing Oracle version metadata.'
      },
      {
        targetUrl: 'https://demo.testfire.net/bank/transfer.aspx',
        place: 'POST',
        parameter: 'amount',
        technique: 'Time-based blind SQL injection',
        note: 'Inference payload with dbms_pipe.receive_message delayed response by 6 seconds.'
      }
    ]
  },
  {
    hostname: 'zero.webappsecurity.com',
    runs: 5,
    records: [
      {
        targetUrl: 'https://zero.webappsecurity.com/login.html',
        place: 'POST',
        parameter: 'user_login',
        technique: 'Boolean-based blind SQL injection',
        note: 'Injected boolean toggles flipped login error responses without rate limiting.'
      },
      {
        targetUrl: 'https://zero.webappsecurity.com/bank/transfer-funds.html',
        place: 'POST',
        parameter: 'amount',
        technique: 'Time-based blind SQL injection',
        note: '1=IF(1=1,SLEEP(4),0) payload produced deterministic waiting period.'
      },
      {
        targetUrl: 'https://zero.webappsecurity.com/search.html',
        place: 'GET',
        parameter: 'searchTerm',
        technique: 'Union query SQL injection',
        note: 'UNION SELECT returned database user banner appended to search results.'
      },
      {
        targetUrl: 'https://zero.webappsecurity.com/account-activity.html',
        place: 'GET',
        parameter: 'account',
        technique: 'Error-based SQL injection',
        note: 'Malformed payload triggered PGSQL error leaking schema information.'
      }
    ]
  },
  {
    hostname: 'www.webscantest.com',
    runs: 5,
    records: [
      {
        targetUrl: 'https://www.webscantest.com/datastore/search_by_id.php',
        place: 'GET',
        parameter: 'id',
        technique: 'Boolean-based blind SQL injection',
        note: 'True/false toggles altered content length while HTML remained valid.'
      },
      {
        targetUrl: 'https://www.webscantest.com/datastore/search-ajax.php',
        place: 'POST',
        parameter: 'search',
        technique: 'Union query SQL injection',
        note: 'UNION-based payload echoed product SKU list in JSON response.'
      },
      {
        targetUrl: 'https://www.webscantest.com/datastore/deleteinfo.php',
        place: 'GET',
        parameter: 'uid',
        technique: 'Stacked queries',
        note: 'Stacked DELETE;SELECT payload returned injected marker row.'
      },
      {
        targetUrl: 'https://www.webscantest.com/datastore/advancedsearch.php',
        place: 'POST',
        parameter: 'category',
        technique: 'Time-based blind SQL injection',
        note: 'SLEEP(3) payload induced average 3.1s responses across retries.'
      }
    ]
  },
  {
    hostname: 'juice-shop.herokuapp.com',
    runs: 5,
    records: [
      {
        targetUrl: 'https://juice-shop.herokuapp.com/rest/products/search',
        place: 'POST',
        parameter: 'q',
        technique: 'Union query SQL injection',
        note: 'GraphQL-style UNION payload extracted hidden product inventory rows.'
      },
      {
        targetUrl: 'https://juice-shop.herokuapp.com/rest/user/login',
        place: 'POST',
        parameter: 'email',
        technique: 'Boolean-based blind SQL injection',
        note: 'Boolean injection bypassed login by forcing true condition.'
      },
      {
        targetUrl: 'https://juice-shop.herokuapp.com/api/Feedbacks/',
        place: 'POST',
        parameter: 'comment',
        technique: 'Error-based SQL injection',
        note: 'SQLite error leak confirmed direct concatenation of comment field.'
      },
      {
        targetUrl: 'https://juice-shop.herokuapp.com/rest/products/{id}',
        place: 'URI',
        parameter: 'id',
        technique: 'Time-based blind SQL injection',
        note: 'Route parameter payload added delay via SELECT randomblob with sleep.'
      }
    ]
  },
  {
    hostname: 'bwapp.honeybot.io',
    runs: 5,
    records: [
      {
        targetUrl: 'https://bwapp.honeybot.io/sqli_1.php',
        place: 'GET',
        parameter: 'movie',
        technique: 'Boolean-based blind SQL injection',
        note: 'Classic OR 1=1 condition enumerated full movie list.'
      },
      {
        targetUrl: 'https://bwapp.honeybot.io/sqli_4.php',
        place: 'POST',
        parameter: 'title',
        technique: 'Error-based SQL injection',
        note: 'Database error with DISTINCT keyword disclosed column count.'
      },
      {
        targetUrl: 'https://bwapp.honeybot.io/sqli_9.php',
        place: 'GET',
        parameter: 'id',
        technique: 'Time-based blind SQL injection',
        note: 'BENCHMARK payload slowed response by 4.7 seconds repetitively.'
      },
      {
        targetUrl: 'https://bwapp.honeybot.io/sqli_12.php',
        place: 'POST',
        parameter: 'search',
        technique: 'Union query SQL injection',
        note: 'UNION payload revealed bee_users table via appended row.'
      }
    ]
  },
  {
    hostname: 'hackazon.webscantest.com',
    runs: 5,
    records: [
      {
        targetUrl: 'https://hackazon.webscantest.com/category.php',
        place: 'GET',
        parameter: 'id',
        technique: 'Boolean-based blind SQL injection',
        note: 'True/false payloads impacted product carousel rendering speed.'
      },
      {
        targetUrl: 'https://hackazon.webscantest.com/api/cart',
        place: 'POST',
        parameter: 'product_id',
        technique: 'Time-based blind SQL injection',
        note: 'Sleep-based payload blocked cart update thread during exploitation.'
      },
      {
        targetUrl: 'https://hackazon.webscantest.com/login.php',
        place: 'POST',
        parameter: 'username',
        technique: 'Boolean-based blind SQL injection',
        note: 'Login accepted payload returning administrator dashboard view.'
      },
      {
        targetUrl: 'https://hackazon.webscantest.com/api/products',
        place: 'GET',
        parameter: 'sort',
        technique: 'Union query SQL injection',
        note: 'UNION ALL payload appended system users to JSON array.'
      }
    ]
  },
  {
    hostname: 'altoro.testfire.net',
    runs: 5,
    records: [
      {
        targetUrl: 'https://altoro.testfire.net/bank/querybalance.aspx',
        place: 'POST',
        parameter: 'txtAccNum',
        technique: 'Boolean-based blind SQL injection',
        note: 'Injected OR clause returned balance data for arbitrary accounts.'
      },
      {
        targetUrl: 'https://altoro.testfire.net/bank/transfer.aspx',
        place: 'POST',
        parameter: 'amount',
        technique: 'Stacked queries',
        note: 'Stacked payload executed INSERT marker into audit log table.'
      },
      {
        targetUrl: 'https://altoro.testfire.net/bank/statement.aspx',
        place: 'GET',
        parameter: 'account',
        technique: 'Union query SQL injection',
        note: 'UNION SELECT produced concatenated card numbers in response.'
      },
      {
        targetUrl: 'https://altoro.testfire.net/bank/account.aspx',
        place: 'GET',
        parameter: 'id',
        technique: 'Error-based SQL injection',
        note: 'Exception trace disclosed DB2 syntax error with payload markers.'
      }
    ]
  },
  {
    hostname: 'mutillidae.local',
    runs: 5,
    records: [
      {
        targetUrl: 'http://mutillidae.local/index.php?page=view-someones-blog.php',
        place: 'GET',
        parameter: 'username',
        technique: 'Boolean-based blind SQL injection',
        note: 'Injected AND 1=1/AND 1=2 payload changed blog visibility toggles.'
      },
      {
        targetUrl: 'http://mutillidae.local/index.php?page=view-someones-blog.php',
        place: 'POST',
        parameter: 'blog_entry',
        technique: 'Error-based SQL injection',
        note: 'MySQL error pointed to CONCAT use within dynamic query builder.'
      },
      {
        targetUrl: 'http://mutillidae.local/index.php?page=search-landing.php',
        place: 'POST',
        parameter: 'query',
        technique: 'Union query SQL injection',
        note: 'UNION injection surfaced users table containing salted hashes.'
      },
      {
        targetUrl: 'http://mutillidae.local/index.php?page=browser-info.php',
        place: 'GET',
        parameter: 'showhints',
        technique: 'Time-based blind SQL injection',
        note: 'SLEEP(3) payload created predictable delay measured over 5 attempts.'
      }
    ]
  }
];

const ensureDir = (dirPath) => {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
};

const formatFilename = (date) => {
  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, '0');
  const day = String(date.getUTCDate()).padStart(2, '0');
  let hours = date.getUTCHours();
  const minutes = String(date.getUTCMinutes()).padStart(2, '0');
  const period = hours >= 12 ? 'pm' : 'am';
  hours = hours % 12;
  if (hours === 0) hours = 12;
  const hourStr = String(hours).padStart(2, '0');
  return `results-${year}${month}${day}_${hourStr}${minutes}${period}.csv`;
};

const escapeCsvCell = (value) => {
  const stringValue = String(value ?? '');
  if (stringValue.includes(',') || stringValue.includes('"') || stringValue.includes('\n')) {
    return '"' + stringValue.replace(/"/g, '""') + '"';
  }
  return stringValue;
};

const toCsv = (rows) => {
  const lines = [HEADER];
  for (const row of rows) {
    lines.push([
      escapeCsvCell(row.targetUrl),
      escapeCsvCell(row.place),
      escapeCsvCell(row.parameter),
      escapeCsvCell(row.technique),
      escapeCsvCell(row.note)
    ].join(','));
  }
  return lines.join('\n');
};

const main = () => {
  ensureDir(BASE_OUTPUT_DIR);

  const start = Date.UTC(2025, 9, 5, 10, 0, 0); // October is month index 9
  let runCounter = 0;

  for (const host of hostCatalog) {
    const hostDir = path.join(BASE_OUTPUT_DIR, host.hostname);
    ensureDir(hostDir);

    for (let run = 0; run < host.runs; run += 1) {
      const timestamp = new Date(start + runCounter * 11 * 60 * 1000);
      const filename = formatFilename(timestamp);
      const filePath = path.join(hostDir, filename);

      const rows = host.records.map((record, idx) => {
        const suffix = NOTE_SUFFIXES[(run + idx) % NOTE_SUFFIXES.length];
        const contextualNote = `${record.note} ${suffix}`;
        return { ...record, note: contextualNote };
      });

      const csv = toCsv(rows);
      fs.writeFileSync(filePath, csv + '\n', 'utf8');
      runCounter += 1;
    }
  }

  console.log(`Generated ${runCounter} SQLMap-style CSV reports in ${BASE_OUTPUT_DIR}`);
};

if (require.main === module) {
  main();
}

module.exports = {
  hostCatalog,
  NOTE_SUFFIXES,
  formatFilename,
  toCsv
};
