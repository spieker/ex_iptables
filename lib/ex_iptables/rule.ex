defmodule ExIptables.Rule do
  @moduledoc """
  Represents an iptables rule. Check the iptables man page for details:
  http://ipset.netfilter.org/iptables.man.html#lbAI
  """
  defstruct protocol: nil,
            source: nil,
            destination: nil,
            match: nil,
            jump: nil,
            goto: nil,
            in_interface: nil,
            out_interface: nil,
            fragment: nil,
            set_counters: nil
end
