import type { CompanyMetadata, MetadataResolver } from './network/discovery.js';
import type { HttpTransport } from './network/transport.js';
import { secureUrl } from './network/transport.js';
import { object, parseJson, ValidationError } from './protocol/wire.js';

export interface ApiTarget { kind: 'openapi' | 'mcp'; apiUrl: string; issuer: string; endpoint: string; resource?: string; scheme: 'DPoP' | 'Bearer' }
export interface AgentBrowserController {
  readonly kind: 'agent-controlled';
  // Trusted adapter: isolated per-session cookies; verified TLS and actual connected-address checks (no private/
  // loopback/link-local peers without narrow explicit configuration). Never log fields. Intercept redirects before
  // following; call validateRedirect, discard the POST body, then navigate. Never replay it on 307/308.
  postForm(input: { url: string; fields: { assertion: string }; validateRedirect(status: number, location: string): string }): Promise<void>;
}
export interface FeedbackReport { kind: 'missing'; task: string; description: string }
export function validateFeedback(value: FeedbackReport): void {
  if (!value || value.kind !== 'missing' || typeof value.task !== 'string' || !value.task.length || [...value.task].length > 200 || typeof value.description !== 'string' || !value.description.length || [...value.description].length > 2000) throw new ValidationError('feedback');
}
export function browserDestination(value: string, domain: string): void {
  const url = secureUrl(value);
  if (url.hostname !== domain.toLowerCase() && !url.hostname.endsWith(`.${domain.toLowerCase()}`)) throw new ValidationError('return_to');
}
export function protectedResourceMetadataUrl(resource: string): string {
  const url = secureUrl(resource); if (url.search) throw new ValidationError('resource');
  return `${url.origin}/.well-known/oauth-protected-resource${url.pathname === '/' ? '' : url.pathname}`;
}
export async function mcpScheme(transport: HttpTransport, issuer: string, resource: string): Promise<'DPoP' | 'Bearer'> {
  const response = await transport.fetch(new Request(protectedResourceMetadataUrl(resource)), { mode: 'discovery' });
  if (response.status !== 200) throw new ValidationError('resource_metadata');
  const metadata = object(parseJson(await response.text()));
  if (metadata.resource !== resource || !Array.isArray(metadata.authorization_servers) || !metadata.authorization_servers.includes(issuer)) throw new ValidationError('resource_issuer');
  for (const server of metadata.authorization_servers) secureUrl(server);
  if ('bearer_methods_supported' in metadata && (!Array.isArray(metadata.bearer_methods_supported) || !metadata.bearer_methods_supported.includes('header'))) throw new ValidationError('bearer_methods_supported');
  if (!Object.hasOwn(metadata, 'dpop_signing_alg_values_supported')) return 'Bearer';
  if (!Array.isArray(metadata.dpop_signing_alg_values_supported) || !metadata.dpop_signing_alg_values_supported.includes('ES256') || !metadata.dpop_signing_alg_values_supported.every(value => typeof value === 'string')) throw new ValidationError('dpop_signing_alg_values_supported');
  return 'DPoP';
}
export async function resolveApiTarget(metadata: CompanyMetadata, resolver: MetadataResolver, transport: HttpTransport, apiUrl: string, destination?: string): Promise<ApiTarget> {
  const api = metadata.document.apis?.find(entry => entry.url === apiUrl);
  const issuer = metadata.authorization?.issuer;
  if (!api || !issuer || !['openapi', 'mcp'].includes(api.type)) throw new ValidationError('api');
  if (api.type === 'mcp') {
    if ((api.resource !== undefined && api.resource !== api.url) || (destination !== undefined && destination !== api.url)) throw new ValidationError('resource');
    const scheme = await mcpScheme(transport, issuer, api.url);
    if (scheme === 'Bearer' && metadata.document.agent?.protocols.some(protocol => protocol.resource === api.url)) throw new ValidationError('resource');
    return { kind: 'mcp', apiUrl, issuer, endpoint: api.url, resource: api.url, scheme };
  }
  // An OpenAPI servers entry is data. The destination host must independently vouch for this issuer.
  if (!destination) throw new ValidationError('destination');
  const url = secureUrl(destination); if (url.search) throw new ValidationError('destination');
  const serving = await resolver.resolveCompany(url.host);
  if (serving.authorization?.issuer !== issuer || serving.document.organization.domain !== url.hostname) throw new ValidationError('destination_issuer');
  return { kind: 'openapi', apiUrl, issuer, endpoint: destination, ...(api.resource ? { resource: api.resource } : {}), scheme: 'DPoP' };
}
