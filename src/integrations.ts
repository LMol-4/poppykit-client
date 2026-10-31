import { companyIdentifier, createMetadataResolver, protectedResourceMetadataUrl } from './network/discovery.js';
import type { CompanyMetadata, MetadataResolver } from './network/discovery.js';
import type { HttpTransport } from './network/transport.js';
import { secureUrl } from './network/transport.js';
import { ValidationError } from './protocol/wire.js';

export interface ApiTarget { kind: 'openapi' | 'mcp'; apiUrl: string; issuer: string; endpoint: string; resource?: string; scheme: 'DPoP' | 'Bearer' }
export interface AgentBrowserController {
  readonly kind: 'agent-controlled';
  // Trusted adapter: isolated per-session cookies; verified TLS and actual connected-address checks (no private/
  // loopback/link-local peers without narrow explicit configuration). Never log fields. Intercept redirects before
  // following; call validateRedirect, discard the POST body, then navigate. Never replay it on 307/308.
  // Load url as a top-level GET, then read its form code in trusted software, outside model context.
  loadJoinForm(url: string): Promise<{ code: string }>;
  postForm(input: { url: string; fields: { code: string }; validateRedirect(status: number, location: string): string }): Promise<void>;
  navigate(url: string): Promise<void>;
}
export interface FeedbackReport { task: string; description: string; [key: string]: unknown }
export function validateFeedback(value: FeedbackReport): void {
  if (!value || typeof value.task !== 'string' || !value.task.length || [...value.task].length > 200 || typeof value.description !== 'string' || !value.description.length || [...value.description].length > 2000) throw new ValidationError('feedback');
}
export function browserDestination(value: string, domain: string): void {
  const url = secureUrl(value);
  if (url.hostname !== domain.toLowerCase() && !url.hostname.endsWith(`.${domain.toLowerCase()}`)) throw new ValidationError('return_to');
}
export { protectedResourceMetadataUrl };
// Discovery is credential-free; a network or malformed-metadata failure never means default authority.
export async function serviceAuthorization(metadata: CompanyMetadata, resolver: MetadataResolver, transport: HttpTransport, endpoint: string, options: { mcp?: boolean; metadataUrl?: string; refresh?: boolean } = {}): Promise<{ resource?: string; scheme: 'DPoP' | 'Bearer' }> {
  secureUrl(endpoint);
  const found = await (resolver.resolveResource ? resolver : createMetadataResolver(transport)).resolveResource!(endpoint, options);
  const domain = `https://${metadata.document.organization.domain.toLowerCase()}`, issuer = metadata.authorization?.issuer;
  if (found) {
    if (found.resource !== endpoint && found.resource !== domain) throw new ValidationError('resource');
    if (issuer && (options.mcp || found.authorization_servers?.length) && !found.authorization_servers?.includes(issuer)) throw new ValidationError('resource_issuer');
    if (!issuer && found.authorization_servers?.length) throw new ValidationError('resource_issuer');
    if (Array.isArray(found.bearer_methods_supported) && !found.bearer_methods_supported.includes('header')) throw new ValidationError('bearer_methods_supported');
  }
  if (options.mcp && issuer && (!found || found.resource !== endpoint)) throw new ValidationError('resource');
  const algorithms = options.mcp ? found?.dpop_signing_alg_values_supported : metadata.authorization?.dpop_signing_alg_values_supported;
  return { ...(options.mcp ? { resource: endpoint } : found && found.resource !== domain ? { resource: found.resource } : {}), scheme: algorithms?.includes('ES256') ? 'DPoP' : 'Bearer' };
}
export async function resolveApiTarget(metadata: CompanyMetadata, resolver: MetadataResolver, transport: HttpTransport, apiUrl: string, destination?: string): Promise<ApiTarget> {
  const api = metadata.document.apis?.find(entry => entry.url === apiUrl), issuer = companyIdentifier(metadata);
  if (!api || !['openapi', 'mcp'].includes(api.type)) throw new ValidationError('api');
  if (api.type === 'mcp') {
    if (destination !== undefined && destination !== api.url) throw new ValidationError('resource');
    return { kind: 'mcp', apiUrl, issuer, endpoint: api.url, ...await serviceAuthorization(metadata, resolver, transport, api.url, { mcp: true }) };
  }
  // A description is data. The destination host independently vouches for the same Company.
  if (!destination) throw new ValidationError('destination');
  const url = secureUrl(destination), serving = await resolver.resolveCompany(url.host);
  if (companyIdentifier(serving) !== issuer || serving.document.organization.domain.toLowerCase() !== url.hostname) throw new ValidationError('destination_issuer');
  return { kind: 'openapi', apiUrl, issuer, endpoint: destination, ...await serviceAuthorization(metadata, resolver, transport, destination) };
}
