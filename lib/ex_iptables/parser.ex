defmodule ExIptables.Parser do
  alias ExIptables.{Chain, Rule}

  def parse(value) do
    res =
      value
      |> String.split("\n")
      |> Enum.map(&split_string/1)
      |> Enum.reduce(%{}, &eval_line/2)
      |> Map.values()

    {:ok, res}
  end

  def split_string(value) do
    value
    |> String.split(~r/ +/)
    |> normalize_args()
  end

  def normalize_args(args) when is_list(args) do
    Enum.map(args, fn
      "--protocol" -> "-p"
      "--source" -> "-s"
      "--destination" -> "-d"
      "--jump" -> "-j"
      "-in-interface" -> "-i"
      "-out-interface" -> "-o"
      val -> val
    end)
  end

  def eval_line(["-P", name, target], res) do
    new_chain =
      res
      |> Map.get(name, %Chain{name: name})
      |> Map.put(:target, target)

    Map.put(res, name, new_chain)
  end

  def eval_line(["-A", name | rule_parts], res) do
    rule = parse_rule(rule_parts)
    chain = Map.get(res, name, %Chain{name: name})
    rules = Map.get(chain, :rules, [])
    rules = rules ++ [rule]
    new_chain = Map.put(chain, :rules, rules)
    Map.put(res, name, new_chain)
  end

  def eval_line(_, res), do: res

  @doc """
  Creates a rule struct by extracting parts of the rule definition.

  ## Example

      iex> ExIptables.Parser.parse_rule("-s 10.1.0.0/16 --jump DROP")
      %Rule{jump: "DROP", source: {false, "10.1.0.0/16"}, rule: "-s 10.1.0.0/16 -j DROP"}

      iex> ExIptables.Parser.parse_rule("! -s 10.1.0.0/16 -j DROP")
      %Rule{jump: "DROP", source: {true, "10.1.0.0/16"}, rule: "! -s 10.1.0.0/16 -j DROP"}

      iex> ExIptables.Parser.parse_rule("! --source 10.1.0.0/16 --destination 10.10.10.10")
      %Rule{destination: {false, "10.10.10.10/32"}, source: {true, "10.1.0.0/16"}, rule: "! -s 10.1.0.0/16 -d 10.10.10.10"}

      iex> ExIptables.Parser.parse_rule("-m string --algo bm --string \"FOO\"")
      %Rule{rule: "-m string --algo bm --string \"FOO\""}

  """

  def parse_rule(rule) when is_binary(rule), do: rule |> split_string() |> parse_rule()

  def parse_rule(parts) when is_list(parts) do
    case Enum.reduce(parts, {false, nil, %Rule{rule: Enum.join(parts, " ")}}, fn
           "!", {false, nil, rule} -> {true, nil, rule}
           "-p", {neg, nil, rule} -> {neg, :protocol, rule}
           "-s", {neg, nil, rule} -> {neg, :source, rule}
           "-d", {neg, nil, rule} -> {neg, :destination, rule}
           "-j", {neg, nil, rule} -> {neg, :jump, rule}
           "-i", {neg, nil, rule} -> {neg, :in_interface, rule}
           "-o", {neg, nil, rule} -> {neg, :out_interface, rule}
           _, {_neg, nil, rule} -> {false, nil, rule}
           value, {_neg, :jump, rule} -> {false, nil, Map.put(rule, :jump, value)}
           value, {neg, key, rule} -> {false, nil, Map.put(rule, key, {neg, value})}
         end) do
      {_, nil, rule} -> rule
    end
  end
end
