defmodule ExIptables.Rule do
  @moduledoc """
  Represents an iptables rule. Check the iptables man page for details:
  http://ipset.netfilter.org/iptables.man.html#lbAI
  """
  defstruct protocol: {false, nil},
            source: {false, nil},
            destination: {false, nil},
            jump: nil,
            in_interface: {false, nil},
            out_interface: {false, nil},
            rule: nil
end
