import { writeFileSync } from 'fs';
import https from 'https'
import { TLSSocket } from 'tls';
import { parseArgs } from 'util';

const daysBetween = (validFrom: Date, validTo: Date) =>
  Math.round(Math.abs(+validFrom - +validTo) / 8.64e7);

const daysRemaining = (validFrom: Date, validTo: Date) => {
  const remaining = daysBetween(validFrom, validTo);

  if (validTo.getTime() < new Date().getTime()) {
    return -remaining;
  }
  return remaining;
};

const SSLCertificationInfo = (options: {
  agent: boolean,
  method: 'get' | 'post' | 'head',
  port: 443 | number,
  hostname: string
}) => {
  return new Promise<{
    subject: string,
    dayRemaining: number,
    valid: boolean,
    validFrom: string,
    validTo: string
  }>((resole, reject) => {
    const req = https.request(options, res => {
      const { valid_from, valid_to, subject } = (res.socket as TLSSocket).getPeerCertificate()

      if (!valid_from || !valid_to) {
        reject(new Error('No certificate!'))
        return
      }

      var validTo = new Date(valid_to)
      resole({
        subject: subject.CN,
        dayRemaining: daysRemaining(new Date(), validTo),
        valid: (res.socket as TLSSocket).authorized || false,
        validFrom: new Date(valid_from).toLocaleString(),
        validTo: validTo.toLocaleString()
      })
    })
      .on('timeout', () => {
        req.destroy()
        reject(new Error("Timeout!"))
      })
      .on('error', err => reject(err))
      .end();
  })
}

const checkCertificateValidity = async (options: {
  agent?: boolean,
  method?: 'get' | 'post' | 'head',
  port?: 443 | number,
  hostname: string
}) =>
  SSLCertificationInfo({
    ...{
      agent: false,
      method: 'get',
      port: 443,
    }, ...options
  }).then(
    res => ({ ...res, isValid: res.dayRemaining > 0 || res.valid })
  );

// try {
const {
  values
} = parseArgs({
  args: process.argv.slice(2), options: {
    agent: { type: 'boolean', short: 'a' },
    method: { type: 'string', short: 'm' }, // 'get' | 'post' | 'head'
    port: { type: 'string', short: 'p' },// 443 | number,
    hostname: { type: 'string', short: 'H' },
  }
});

// console.log(Object.entries(values).filter(v => v))

checkCertificateValidity({ hostname: 'www.google.com' }).then(res => {
  if (res && res.isValid) {
    writeFileSync('certificateCheck.json', JSON.stringify(res))
    console.log(res)
    if (res.dayRemaining < 30) {
      console.log(`憑證快到期，僅剩 ${res.dayRemaining} 天`)
    }
  }
})
// } catch (error) {

// }
