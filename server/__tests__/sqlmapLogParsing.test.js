/* eslint-env jest */
const fs = require('fs');
const os = require('os');
const path = require('path');

const SQLMapIntegration = require('../sqlmap');

describe('SQLMap log parsing', () => {
  let integration;
  let validateSpy;
  let tempDir;

  beforeAll(() => {
    validateSpy = jest
      .spyOn(SQLMapIntegration.prototype, 'validateSQLMapInstallation')
      .mockImplementation(() => Promise.resolve());
  });

  afterAll(() => {
    if (validateSpy) validateSpy.mockRestore();
  });

  beforeEach(() => {
    tempDir = path.join(os.tmpdir(), `sqlmap-log-${Date.now()}`);
    process.env.SQLMAP_TEMP_DIR = tempDir;
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true });
    }
    integration = new SQLMapIntegration();
  });

  afterEach(() => {
    if (integration && integration.tempDir) {
      try {
        fs.rmSync(integration.tempDir, { recursive: true, force: true });
      } catch (_) {}
    }
    integration = null;
    if (tempDir && fs.existsSync(tempDir)) {
      try {
        fs.rmSync(tempDir, { recursive: true, force: true });
      } catch (_) {}
    }
    delete process.env.SQLMAP_TEMP_DIR;
  });

  it('captures all sqlmap-confirmed techniques for a single parameter', () => {
    const booleanPayload = "title=bee' AND 6649=(SELECT (CASE WHEN (6649=6649) THEN 6649 ELSE (SELECT 1071 UNION SELECT 4464) END))-- dPCE&action=search";
    const errorPayload = "title=bee' AND EXTRACTVALUE(7609,CONCAT(0x5c,0x716b627a71,(SELECT (ELT(7609=7609,1))),0x7162767171)) AND 'kXeb'='kXeb&action=search";
    const unionPayload = "title=bee' UNION ALL SELECT NULL,NULL,NULL,CONCAT(0x716b627a71,0x706f62677547427a5861774578544f4a674759686959726666426f64594d466144456655676b4d45,0x7162767171),NULL,NULL,NULL-- -&action=search";

    const sampleLog = [
      "[12:01:00] [INFO] testing parameter 'title'", // initial context
      '[12:01:05] [INFO] sqlmap identified the following injection point(s) with a total of 0 HTTP(s) requests:',
      '---',
      'Parameter: title (GET)',
      `    Type: boolean-based blind`,
      `    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)`,
      `    Payload: ${booleanPayload}`,
      `    Type: MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)` ,
      `    Payload: ${errorPayload}`,
      `    Type: Generic UNION query (NULL) - 7 columns`,
      `    Payload: ${unionPayload}`,
      '---',
      '[12:01:06] [INFO] some trailing message'
    ].join('\n');

    const { findings, analysis } = integration.parseLogFile(sampleLog);

    const targetParam = analysis.parameters.find((entry) => entry.name === 'title');
    expect(targetParam).toBeTruthy();
    expect(targetParam.place).toBe('GET');
    expect(targetParam.techniques).toEqual(
      expect.arrayContaining([
        'Boolean-based blind SQL injection',
        'Error-based SQL injection',
        'Union query SQL injection'
      ])
    );
    expect(targetParam.payloads).toEqual(
      expect.arrayContaining([booleanPayload, errorPayload, unionPayload])
    );

    const reportedTechniques = findings
      .filter((finding) => finding.parameter === 'title' && finding.type === 'vulnerability')
      .map((finding) => finding.technique);

    expect(reportedTechniques).toHaveLength(3);
    expect(reportedTechniques).toEqual(
      expect.arrayContaining([
        'Boolean-based blind SQL injection',
        'Error-based SQL injection',
        'Union query SQL injection'
      ])
    );
  });
});
