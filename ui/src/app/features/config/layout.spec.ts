import openapi from '../../../../../docs/api/openapi.json';
import { documentSchema } from './form-schema';
import { ACRONYMS, SPELLED, fieldLabel } from './layout';

/**
 * Words in the document's field names that read as they are written. A
 * new word must go here, in ACRONYMS, or in SPELLED, so that someone
 * decides how it reads (#339).
 */
const PLAIN = new Set(
  `action address addresses advert allowed anti at backup bandwidth block bond
  buckets cake certificate certificates challenge channel check checksum
  client clients cluster comment connections conntrack credentials daily
  delay destination directory domain dynamic elements email enabled endpoint
  established extra forwarders forwards from gateway generations group
  hairpin hash hold hook hostname hourly intercept interval keepalive key keys kill
  last lease length limit listen lockout log logging management max members
  metrics minutes mode monthly names network networks nodes objects offload
  options order pair password peer peers ping policy pool port ports position
  preempt prefix preshared primary priority private proto protocol provider
  public rate raw records remote repository reservations retention role route
  router rules schedule schema serve servers size source sources subnet
  suffixes switch sync time timeout to type unicast updates use web weekly
  window yearly zone zones`.split(/\s+/),
);

/** Every property name anywhere in the document's schema. */
function names(o: unknown, out = new Set<string>()): Set<string> {
  if (Array.isArray(o)) o.forEach((x) => names(x, out));
  else if (o && typeof o === 'object') {
    for (const [k, v] of Object.entries(o)) {
      if (k === 'properties' && v && typeof v === 'object' && !Array.isArray(v))
        Object.keys(v).forEach((n) => out.add(n));
      names(v, out);
    }
  }
  return out;
}

describe('fieldLabel', () => {
  it('knows how every word in the document reads', () => {
    const words = new Set(
      [...names(documentSchema(openapi as never))].flatMap((n) => n.split('_')).filter(Boolean),
    );
    const unknown = [...words]
      .filter((w) => !PLAIN.has(w) && !ACRONYMS.has(w) && !(w in SPELLED))
      .sort();
    expect(unknown).toEqual([]);
  });

  it('writes acronyms and words of its own', () => {
    expect(fieldLabel('lldp')).toBe('LLDP');
    expect(fieldLabel('client_allowed_ips')).toBe('Client allowed IPs');
    expect(fieldLabel('extra_vips')).toBe('Extra VIPs');
    expect(fieldLabel('advert_interval_cs')).toBe('Advert interval (cs)');
    expect(fieldLabel('preempt_delay_s')).toBe('Preempt delay (s)');
    expect(fieldLabel('dport')).toBe('Destination port');
    expect(fieldLabel('kid')).toBe('Key ID');
    expect(fieldLabel('ca')).toBe('CA');
  });
});
