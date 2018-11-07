defmodule ExIptables do
  @moduledoc """
  This module provides wrapper functions around the iptables CLI. It uses
  adapters for executing the commands, in order to provide a convenient way to
  test your application.

  Use the `ExIptables.Adapters.FakeAdapter` for testing.
  """
  alias ExIptables.Chain
  alias ExIptables.Rule

  @adapter Application.get_env(:ex_iptables, :adapter, ExIptables.Adapters.CliAdapter)

  def clear, do: @adapter.clear()

  @doc """
  Append a rule to the end of the selected chain. When the source and/or
  destination names resolve to more than one address, a rule will be added for
  each possible address combination.

  ## Example

      iex> {:ok, _} = ExIptables.append("FORWARD", %ExIptables.Rule{source: "10.0.0.0/8", jump: "DROP"})
      ...> ExIptables.list("FORWARD")
      {:ok, %ExIptables.Chain{name: "FORWARD", target: "ACCEPT", rules: [%ExIptables.Rule{
        protocol: nil,
        source: "10.0.0.0/8",
        destination: nil,
        match: nil,
        jump: "DROP",
        goto: nil,
        in_interface: nil,
        out_interface: nil,
        fragment: nil,
        set_counters: nil
      }]}}

      iex> ExIptables.append("MISSING", %ExIptables.Rule{source: "10.0.0.0/8", jump: "DROP"})
      {:error, 1}
  """
  def append(chain, %Rule{} = rule), do: @adapter.cmd(["--append", chain] ++ rule_to_args(rule))

  @doc """
  Check whether a rule matching the specification does exist in the selected
  chain. This command uses the same logic as `delete/2`.

  ## Example

      iex> {:ok, _} = ExIptables.append("FORWARD", %ExIptables.Rule{source: "10.0.0.0/8", jump: "DROP"})
      ...> ExIptables.check("FORWARD", %ExIptables.Rule{source: "10.0.0.0/8", jump: "DROP"})
      true

      iex> ExIptables.check("FORWARD", %ExIptables.Rule{source: "10.0.0.0/8", jump: "DROP"})
      false

      iex> ExIptables.check("MISSING", %ExIptables.Rule{source: "10.0.0.0/8", jump: "DROP"})
      false

  """
  def check(chain, %Rule{} = rule) do
    case @adapter.cmd(["--check", chain] ++ rule_to_args(rule)) do
      {:ok, ""} -> true
      {:error, _} -> false
    end
  end

  @doc """
  Delete the matching rules from the selected chain.

  ## Example

      iex> {:ok, _} = ExIptables.append("FORWARD", %ExIptables.Rule{source: "10.0.0.0/8", jump: "DROP"})
      ...> {:ok, %ExIptables.Chain{rules: rules}} = ExIptables.list("FORWARD")
      ...> 1 = Enum.count(rules)
      ...> {:ok, _} = ExIptables.delete("FORWARD", %ExIptables.Rule{source: "10.0.0.0/8", jump: "DROP"})
      ...> ExIptables.list("FORWARD")
      {:ok, %ExIptables.Chain{name: "FORWARD", target: "ACCEPT", rules: []}}

      iex> ExIptables.delete("FORWARD", %ExIptables.Rule{source: "10.0.0.0/8", jump: "DROP"})
      {:error, 1}

      iex> ExIptables.delete("MISSING", %ExIptables.Rule{source: "10.0.0.0/8", jump: "DROP"})
      {:error, 1}

  """
  def delete(chain, %Rule{} = rule), do: @adapter.cmd(["--delete", chain] ++ rule_to_args(rule))

  @doc """
  Insert one or more rules in the selected chain as the given rule number. So,
  if the rule number is 1, the rule or rules are inserted at the head of the
  chain.

  ## Example

      iex> ExIptables.append("FORWARD", %ExIptables.Rule{source: "10.1.0.0/16", jump: "DROP"})
      ...> ExIptables.append("FORWARD", %ExIptables.Rule{source: "10.3.0.0/16", jump: "DROP"})
      ...> ExIptables.insert("FORWARD", 2, %ExIptables.Rule{source: "10.2.0.0/16", jump: "DROP"})
      ...> ExIptables.list("FORWARD")
      {:ok, %ExIptables.Chain{
        name: "FORWARD",
        rules: [
          %ExIptables.Rule{
            destination: nil,
            fragment: nil,
            goto: nil,
            in_interface: nil,
            jump: "DROP",
            match: nil,
            out_interface: nil,
            protocol: nil,
            set_counters: nil,
            source: "10.1.0.0/16"
          },
          %ExIptables.Rule{
            destination: nil,
            fragment: nil,
            goto: nil,
            in_interface: nil,
            jump: "DROP",
            match: nil,
            out_interface: nil,
            protocol: nil,
            set_counters: nil,
            source: "10.2.0.0/16"
          },
          %ExIptables.Rule{
            destination: nil,
            fragment: nil,
            goto: nil,
            in_interface: nil,
            jump: "DROP",
            match: nil,
            out_interface: nil,
            protocol: nil,
            set_counters: nil,
            source: "10.3.0.0/16"
          }
        ]
      }}

  """
  def insert(chain, rulenum, %Rule{} = rule),
    do: @adapter.cmd(["--insert", chain, "#{rulenum}"] ++ rule_to_args(rule))

  @doc """
  Replace a rule in the selected chain. If the source and/or destination names
  resolve to multiple addresses, the command will fail. Rules are numbered
  starting at 1.
  """
  def replace(chain, rulenum, %Rule{} = rule),
    do: @adapter.cmd(["--replace", chain, rulenum] ++ rule_to_args(rule))

  @doc """
  List all chains including the rules.

  ## Example

      iex> ExIptables.list()
      {:ok, [
              %ExIptables.Chain{name: "FORWARD", rules: [], target: "ACCEPT"},
              %ExIptables.Chain{name: "INPUT", rules: [], target: "ACCEPT"},
              %ExIptables.Chain{name: "OUTPUT", rules: [], target: "ACCEPT"}
            ]}

  """
  def list() do
    @adapter.cmd(["--list-rules"])
    |> handle_list_rules_result()
  end

  @doc """
  List the selected chain including the rules.

  ## Example

      iex> ExIptables.list("FORWARD")
      {:ok, %ExIptables.Chain{name: "FORWARD", target: "ACCEPT", rules: []}}

      iex> ExIptables.list("MISSING")
      {:error, 1}

  """
  def list(chain) do
    case ["--list-rules", chain] |> @adapter.cmd() |> handle_list_rules_result() do
      {:ok, list} -> {:ok, List.first(list)}
      error -> error
    end
  end

  @doc """
  Flushes all chains in the table. This is equivalent to deleting all the rules
  one by one.
  """
  def flush(), do: @adapter.cmd(["--flush"])

  @doc """
  Flushes all chains in given chain. This is equivalent to deleting all the
  rules one by one.
  """
  def flush(chain), do: @adapter.cmd(["--flush", chain])

  @doc """
  Zero the packet and byte counters in all chains.
  """
  def zero(), do: @adapter.cmd(["--zero"])

  @doc """
  Zero the packet and byte counters in the given chain.
  """
  def zero(chain), do: @adapter.cmd(["--zero", chain])

  @doc """
  Zero the packet and byte counters of the given rule in a chain.
  """
  def zero(chain, rulenum), do: @adapter.cmd(["--zero", chain, rulenum])

  @doc """
  Create a new user-defined chain by the given name. There must be no target of
  that name already.
  """
  def new_chain(chain), do: @adapter.cmd(["--new-chain", chain])

  @doc """
  Delete all optional user-defined chains. There must be no references to the
  chains. If there are, you must delete or replace the referring rules before
  the chains can be deleted. The chains must be empty, i.e. not contain any
  rules.
  """
  def delete_chain(), do: @adapter.cmd(["--delete-chain"])

  @doc """
  Delete the optional user-defined chain specified. There must be no references
  to the chain. If there are, you must delete or replace the referring rules
  before the chain can be deleted. The chain must be empty, i.e. not contain any
  rules.
  """
  def delete_chain(chain), do: @adapter.cmd(["--delete-chain", chain])

  @doc """
  Set the policy for the chain to the given target. See the section TARGETS for
  the legal targets. Only built-in (non-user-defined) chains can have policies,
  and neither built-in nor user-defined chains can be policy targets.

  ## Example

      iex> ExIptables.policy("FORWARD", "DROP")
      ...> ExIptables.list("FORWARD")
      {:ok, %ExIptables.Chain{name: "FORWARD", target: "DROP", rules: []}}

      iex> ExIptables.policy("MISSING", "DROP")
      {:error, 1}

  """
  def policy(chain, target), do: @adapter.cmd(["--policy", chain, target])

  @doc """
  Rename the user specified chain to the user supplied name. This is cosmetic,
  qand has no effect on the structure of the table.
  """
  def rename_chain(old_name, new_name), do: @adapter.cmd(["--rename-chain", old_name, new_name])

  defp rule_to_args(%Rule{} = rule) do
    rule
    |> Map.from_struct()
    |> Enum.reduce([], fn
      {_, nil}, args ->
        args

      {key, val}, args ->
        key =
          key
          |> Atom.to_string()
          |> String.replace("_", "-")

        args ++ ["--#{key}", val]
    end)
  end

  def handle_list_rules_result({:error, _} = error), do: error

  def handle_list_rules_result({:ok, value}) do
    res =
      value
      |> String.split("\n")
      |> Enum.map(&String.split(&1, ~r/ +/))
      |> Enum.reduce(%{}, &reduce_list_line/2)
      |> Map.values()

    {:ok, res}
  end

  defp reduce_list_line(["-P", name, target], res) do
    new_chain =
      res
      |> Map.get(name, %Chain{name: name})
      |> Map.put(:target, target)

    Map.put(res, name, new_chain)
  end

  defp reduce_list_line(["-A", name | args], res) do
    [_ | moved_args] = args

    rule =
      [Enum.take_every(args, 2), Enum.take_every(moved_args, 2)]
      |> Enum.zip()
      |> Enum.reduce(%Rule{}, fn
        {"-p", value}, rule -> %Rule{rule | protocol: value}
        {"-s", value}, rule -> %Rule{rule | source: value}
        {"-d", value}, rule -> %Rule{rule | destination: value}
        {"-m", value}, rule -> %Rule{rule | match: value}
        {"-j", value}, rule -> %Rule{rule | jump: value}
        {"-g", value}, rule -> %Rule{rule | goto: value}
        {"-i", value}, rule -> %Rule{rule | in_interface: value}
        {"-o", value}, rule -> %Rule{rule | out_interface: value}
        {"-f", value}, rule -> %Rule{rule | fragment: value}
        {"-c", value}, rule -> %Rule{rule | set_counters: value}
      end)

    chain = Map.get(res, name, %Chain{name: name})
    rules = Map.get(chain, :rules, [])
    rules = rules ++ [rule]
    new_chain = Map.put(chain, :rules, rules)
    Map.put(res, name, new_chain)
  end

  defp reduce_list_line([""], res), do: res
end
