# This file is responsible for configuring your application
# and its dependencies with the aid of the Mix.Config module.
use Mix.Config

# By default, the umbrella project as well as each child
# application will require this configuration file, ensuring
# they all use the same configuration. While one could
# configure all applications here, we prefer to delegate
# back to each application for organization purposes.
import_config "../apps/*/config/config.exs"

# Sample configuration (overrides the imported configuration above):

config :logger,
  handle_otp_reports: false,
  handle_sasl_reports: false

config :logger, :debug,
  level: :info,
  format: "$date $time [$level] $metadata⋅$message⋅\n",
  metadata: [:module, :function, :request_id]

import_config "#{Mix.env()}.exs"
