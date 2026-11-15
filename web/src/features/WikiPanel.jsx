import React, { useState } from 'react'
import { Card } from '@heroui/react'
import { t } from '../i18n.jsx'
import { ExpandableRow } from '../components/details.jsx'

export function WikiPanel() {
  const [openArticle, setOpenArticle] = useState('')
  const expanded = openArticle === 'domain-ca-export'

  return (
    <Card className="wiki">
      <div className="section-title">
        <div>
          <h2>{t('ui.wiki')}</h2>
        </div>
      </div>
      <ExpandableRow
        title={t('ui.export_the_domain_ca_public_certificate')}
        expanded={expanded}
        onExpandedChange={(open) => setOpenArticle(open ? 'domain-ca-export' : '')}
      >
        {expanded && (
          <div className="accordion-detail wiki-body">
            <p>
              {t('ui.bruecke_needs_the_public_ad_cs_ca_certificate_that_issued_spaced')}
              <code>{t('ui.export_pfxcertificate')}</code>.
            </p>
            <p>
              {t('ui.windows_startup_runs_write_spaced')}
              <code>{t('ui.c_programdata_bruecke_bootstrap_log')}</code>
              {t('ui.and_upload_redacted_diagnostics_to_bootstrap_logs_check_pe_spaced')}
            </p>
            <ol className="wiki-steps">
              <li>{t('ui.run_these_commands_on_a_domain_joined_windows_computer_aft')}</li>
              <li>{t('ui.use_the_generated_pem_file_in_authentication_domain_cas')}</li>
              <li>
                {t('ui.ignore_microsoft_entra_azure_ad_spaced')}
                <code>{t('ui.ms_organization')}</code>
                {t('ui.device_certificates_for_this_use_case_spaced')}
              </li>
              <li>{t('ui.if_computers_use_multiple_issuing_cas_repeat_this_for_each')}</li>
            </ol>
            <h4>{t('ui.powershell_find_the_ad_cs_computer_cert_and_export_its_iss')}</h4>
            <pre className="command-block">
              <code>{`$clientAuthOid = '1.3.6.1.5.5.7.3.2'
$candidates = Get-ChildItem Cert:\\LocalMachine\\My |
  Where-Object { $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) } |
  Where-Object {
    $eku = @($_.EnhancedKeyUsageList)
    $eku.Count -eq 0 -or ($eku | Where-Object { $_.ObjectId -eq $clientAuthOid })
  } |
  Where-Object { $_.Issuer -notmatch 'MS-Organization' -and $_.Subject -notmatch 'MS-Organization' } |
  Sort-Object NotAfter -Descending |
  Select-Object Subject, Issuer, Thumbprint, NotAfter

$candidates | Format-List

$thumbprint = '<AD CS computer certificate thumbprint>'
$cert = Get-ChildItem Cert:\\LocalMachine\\My\\$thumbprint

$chain = New-Object Security.Cryptography.X509Certificates.X509Chain
$chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
$chain.Build($cert) | Out-Null

$chain.ChainElements | ForEach-Object {
  [PSCustomObject]@{
    Subject    = $_.Certificate.Subject
    Issuer     = $_.Certificate.Issuer
    Thumbprint = $_.Certificate.Thumbprint
    NotAfter   = $_.Certificate.NotAfter
  }
} | Format-List

if ($chain.ChainElements.Count -lt 2) { throw 'selected certificate has no issuing CA in its chain' }
$issuingCa = $chain.ChainElements[1].Certificate

Export-Certificate -Cert $issuingCa -FilePath .\\domain-ca.cer
certutil -encode .\\domain-ca.cer .\\domain-ca.pem`}</code>
            </pre>
            <p>
              {t('ui.if_spaced')}
              <code>{t('ui.export_certificate')}</code>
              {t('ui.says_spaced')}
              <code>{t('ui.parameterargumentvalidationerrornullnotallowed')}</code>
              {t('ui.the_selected_certificate_had_no_issuing_ca_in_its_chain_th_spaced')}
              <code>{t('ui.ms_organization')}</code>
              {t('ui.device_certificates_are_present_not_an_ad_cs_computer_cert_spaced')}
            </p>
            <h4>{t('ui.if_no_ad_cs_computer_certificate_appears')}</h4>
            <p>{t('ui.enable_computer_certificate_auto_enrollment_by_gpo_confirm_spaced')}</p>
            <pre className="command-block">
              <code>{`gpupdate /force
certutil -pulse`}</code>
            </pre>
            <p>{t('ui.gpo_path_computer_configuration_policies_windows_settings_spaced')}</p>
            <p>
              {t('ui.template_path_spaced')}
              <code>{t('ui.certtmpl_msc')}</code>
              {t('ui.certificate_templates_computer_or_workstation_authenticati_spaced')}
              <code>{t('ui.certsrv_msc')}</code>
              {t('ui.if_needed_spaced')}
            </p>
            <h4>{t('ui.cmd_export_from_an_enterprise_ca')}</h4>
            <pre className="command-block">
              <code>{`certutil -config - -ping
certutil -config "CAHOST\\CA-NAME" -ca.cert domain-ca.cer
certutil -encode domain-ca.cer domain-ca.pem
type domain-ca.pem`}</code>
            </pre>
            <p>
              {t('ui.replace_spaced')}
              <code>{t('ui.cahost_ca_name')}</code>
              {t('ui.with_the_ca_config_name_shown_by_the_first_command_the_pem_spaced')}
              <code>{t('ui.begin_certificate')}</code>.
            </p>
          </div>
        )}
      </ExpandableRow>
    </Card>
  )
}
