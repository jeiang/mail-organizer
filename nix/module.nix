self: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkIf mkOption types;
  cfg = config.services.mail-organizer;
  credentials = "/run/credentials/mail-organizer.service";
  dropNulls = lib.filterAttrs (_: v: v != null);
  settings = {
    db = "/var/lib/mail-organizer/mail.db";
    listen = cfg.listen;
    metrics_listen = cfg.metricsListen;
    write_cap = cfg.writeCap;
    trace_url_template = cfg.traceUrlTemplate;
    telemetry = dropNulls {
      enabled = cfg.telemetry.enable;
      inherit (cfg.telemetry) endpoint;
      service_name = cfg.telemetry.serviceName;
      sample_ratio = cfg.telemetry.sampleRatio;
    };
    account =
      lib.mapAttrsToList (name: a: {
        inherit name;
        inherit (a) preset login;
        password_file = "${credentials}/${name}";
      })
      cfg.accounts;
  };
  configFile = (pkgs.formats.toml {}).generate "mail-organizer.toml" settings;
in {
  options.services.mail-organizer = {
    enable = mkEnableOption "mail-organizer, which files read IMAP inbox mail into folders";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "mail-organizer.packages.\${system}.default";
      description = "The mail-organizer package.";
    };

    listen = mkOption {
      type = types.str;
      default = "127.0.0.1:8490";
      description = "Address of the web UI with rule editing; keep it on loopback.";
    };

    metricsListen = mkOption {
      type = types.str;
      default = "127.0.0.1:9490";
      description = "Address serving `/metrics` and `/healthz`; keep it off public interfaces.";
    };

    writeCap = mkOption {
      type = types.ints.positive;
      default = 100;
      description = "Most mailbox writes per account per pass.";
    };

    traceUrlTemplate = mkOption {
      type = types.str;
      default = "";
      description = "URL the UI links a decision's trace to, with `{trace_id}` replaced. Empty: show the id only.";
    };

    accounts = mkOption {
      type = types.attrsOf (types.submodule {
        options = {
          preset = mkOption {
            type = types.enum ["icloud" "gmail"];
            description = "Provider, which sets the IMAP host and mailbox handling.";
          };
          login = mkOption {
            type = types.str;
            description = "IMAP login name.";
          };
          passwordFile = mkOption {
            type = types.path;
            description = "File holding the app password, passed to the service as a systemd credential.";
          };
        };
      });
      default = {};
      description = "IMAP accounts, keyed by name. Names must stay stable: stored history refers to them.";
    };

    telemetry = {
      enable = mkEnableOption "OpenTelemetry span export to an OTLP/HTTP collector";

      endpoint = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          OTLP/HTTP base URL; spans are posted to `<endpoint>/v1/traces`.
          Null: `http://127.0.0.1:4318`, the collector's default receiver.
        '';
      };

      serviceName = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "`service.name` on exported spans. Null: `mail-organizer`.";
      };

      sampleRatio = mkOption {
        type = types.nullOr (types.numbers.between 0.0 1.0);
        default = null;
        description = ''
          Fraction of new traces sampled, 0.0..=1.0. Children keep their
          parent's sampling decision, so a trace is sampled or not as a
          whole. Null: 1.0.
        '';
      };
    };

    monitoring = {
      ruleFile = mkOption {
        type = types.path;
        readOnly = true;
        default = ./monitoring/rules.yml;
        description = "Prometheus alert rules for mail-organizer's metrics, for services.prometheus.ruleFiles or vmalert.";
      };

      dashboardFile = mkOption {
        type = types.path;
        readOnly = true;
        default = ./monitoring/dashboard.json;
        description = "Grafana dashboard for mail-organizer, for Grafana dashboard provisioning.";
      };
    };
  };

  config = mkIf cfg.enable {
    users.users.mail-organizer = {
      isSystemUser = true;
      group = "mail-organizer";
    };
    users.groups.mail-organizer = {};

    environment.etc."mail-organizer/config.toml".source = configFile;
    environment.systemPackages = [cfg.package];

    systemd.services.mail-organizer = {
      description = "mail-organizer";
      wantedBy = ["multi-user.target"];
      wants = ["network-online.target"];
      after = ["network-online.target"];
      restartTriggers = [configFile];
      environment.RUST_LOG = "info";
      serviceConfig = {
        User = "mail-organizer";
        Group = "mail-organizer";
        ExecStartPre = "${lib.getExe cfg.package} --config /etc/mail-organizer/config.toml migrate";
        ExecStart = "${lib.getExe cfg.package} --config /etc/mail-organizer/config.toml serve";
        Restart = "on-failure";
        RestartSec = 10;
        LoadCredential = lib.mapAttrsToList (name: a: "${name}:${a.passwordFile}") cfg.accounts;
        StateDirectory = "mail-organizer";
        StateDirectoryMode = "0700";
        UMask = "0077";
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        NoNewPrivileges = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        RestrictAddressFamilies = ["AF_INET" "AF_INET6" "AF_UNIX"];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = ["@system-service" "~@privileged"];
        CapabilityBoundingSet = "";
      };
    };
  };
}
