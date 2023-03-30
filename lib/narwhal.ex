defmodule Misc.Narwhal.Types do
  @moduledoc """

  I define out the types for the Narwhal protocol. I version out all
  my types for easier upgrading down the line
  """
  #############################################################
  #                         Types                             #
  #                REFACTOR THESE TO DEFSTRUCT                #
  #    https://elixir-lang.org/getting-started/structs.html   #
  #############################################################

  @type block_1 :: %{
    transactions: list(),
    certificates: list()
  }

  @type block_structure_1 :: %{
    block: block_1(),
    round: integer(),
    pub_key: binary()
  }

  # with the block being signed
  @type signed_block_1 :: {block_structure_1(), binary()}

  @type cert_1 :: %{
    digest: binary(),
    signatures: list(),
    validator: binary(),
    round: integer()
  }

  @type signature :: %{signed: binary(), pub_key: binary()}

  @type partial_block_1 :: %{certs: list(), transactions: list()}

  @type network() :: %{
    # this is the value of 2f + 1 I guess
    total_signatures_required: integer(),
    round: integer(),
    # Map the hash of a block to the block itself.
    blocks: map(),
    # we keep track of the signed nodes at this round
    signed_blocks_of_the_round: MapSet.t(),
    public_key: binary(),
    private_key: binary()
  }

  @spec new_network(integer()) :: network()
  def new_network(total_signatures_needed) do
    {pub, priv} = :crypto.generate_key(:rsa, {1024,65537})
    %{total_signatures_required: total_signatures_needed,
      round: 0,
      blocks: Map.new(),
      signed_blocks_of_the_round: MapSet.new(),
      public_key: pub,
      private_key: priv
    }
  end

  def new_partial_block() do
    %{certificates: [], transactions: []}
  end
end

defmodule Misc.Narwhal.Validator do
  @moduledoc """
  I am a validator for the Narwhal protocol.

  We act as a supervisor, supervising a primary node that does the
  logic, and a communication node, that communicates between other
  validators.

  ### Examples

  {:ok, pid} = Misc.Narwhal.Validator.start_link(3)

  Misc.Narwhal.Validator.get_primary(pid)

  Misc.Narwhal.Primary.get_state(Misc.Narwhal.Validator.get_primary(pid))

  """

  use Supervisor
  alias Misc.Narwhal.Types, as: T

  #############################################################
  #                     Main Behavior                         #
  #############################################################

  def start_link(inital_state) do
    Supervisor.start_link(__MODULE__, inital_state)
  end

  @impl true
  def init({:resuming, config, block}) do
    children =
      [ {Misc.Narwhal.Primary, {:block, config, block}},
        {Misc.Narwhal.Communicator, []}
      ]
    Supervisor.init(children, strategy: :one_for_one)
  end

  def init({:config, config}) do
    children =
      [ {Misc.Narwhal.Primary, config},
        {Misc.Narwhal.Communicator, []}
      ]
    Supervisor.init(children, strategy: :one_for_one)
  end

  def init(_) do
    children =
      [ {Misc.Narwhal.Primary, T.new_network(3)},
        {Misc.Narwhal.Communicator, []}
      ]
    Supervisor.init(children, strategy: :one_for_one)
  end


  #############################################################
  #                    Helper Functions                       #
  #############################################################

  defp get(module_name, pid) do
    pid
    |> Supervisor.which_children()
    |> Enum.find(:fail, &(elem(&1, 0) == module_name))
    |> elem(1)
  end

  def get_primary(pid),
    do: get(Misc.Narwhal.Primary, pid)

  def get_communicator(pid),
    do: get(Misc.Narwhal.Communicator, pid)
end

defmodule Misc.Narwhal.Primary do
  @moduledoc """

  We represent the primary logic of a Narwhal valdiator. We are a
  State machine between the following states:

  - block_creation
  - signature_collection
  """

  alias Misc.Narwhal.Types, as: T

  # Define out the records for the protocol
  @type state_1 :: %{
    network: T.network(),
    data: any()
  }

  @behaviour :gen_statem

  def callback_mode, do: :state_functions

  @type init() :: T.network | {:block, T.network, T.partial_block_1()}

  # TODO Use an AGENT to persist the last state before crash
  @spec init(init()) :: {:ok, :block_creation, state_1}
  def init({:block, config, block}),
    do: {:ok, :block_creation, %{network: config, data: block}}

  def init(net),
    do: {:ok,
         :block_creation,
         %{network: net, data: T.new_partial_block()}}

  def start_link(arg) do
    :gen_statem.start_link(__MODULE__, arg, [])
  end

  #############################################################
  #             Client API CALLING FUNCTIONS                  #
  #############################################################

  def new_transaction(primary, transaction) do
    :gen_statem.cast(primary, {:new_transaction, transaction})
  end

  def new_certificate(primary, certification) do
    :gen_statem.call(primary, {:new_certificate, certification})
  end

  @spec sign_block(pid(), T.signed_block_1()) :: any()
  def sign_block(primary, block) do
    :gen_statem.call(primary, {:sign_block, block})
  end

  def get_state(primary) do
    :gen_statem.call(primary, :get_state)
  end

  #############################################################
  #                     Server States                         #
  #############################################################

  def block_creation(:cast, {:new_transaction, transaction}, state) do
    # we should check for validity, but alas Ι don't
    if valid_transaction?(transaction) do
      {_, new_state} =
        get_and_update_in(state, [:data, :transactions], &{nil, [transaction | &1]})
      {:keep_state, new_state, []}
    else
      {:keep_state, state, []}
    end
  end

  def block_creation({:call, from}, {:new_certificate, cert}, state) do
      # the check is fake for now
      # this call can happen in the nested if to save computation... who cares
      net = state.network
      path_to_cert = [:data, :certificates]
      {num_certs, new_state} =
        get_and_update_in(state, path_to_cert , &{length(&1) + 1, [cert | &1]})
      cond do
        not valid_certificate?(cert) ->
          {:keep_state, state, [{:reply, from, :error}]}
        num_certs < state.network.total_signatures_required ->
          {:keep_state, new_state, [{:reply, from, :ack}]}
        true ->
          {block, sig} = create_block(new_state)
          digest       = digest_block(block)
          new_net      = Map.put(net, :blocks, Map.put(net.blocks, digest, block))
          wip_cert     = %{signatures: [],
                           validator:  new_net.public_key,
                           digest:     digest,
                           round:      new_net.round}
          new_state    = %{network: new_net, data: wip_cert}
          reply        = {:reply, from, {block, sig}}
          {:next_state, :signature_collection, new_state, [reply]}
      end
  end

  def block_creation({:call, from}, {:sign_block, block}, state) do
    sign_external_block(from, block, state)
  end

  def block_creation({:call, from}, :get_state, state) do
    {:keep_state, state, [{:reply, from, state}]}
  end

  def block_creation(call, message, state) do
    handle_unsupported(call, state, message, :signature_collection)
  end

  def signature_collection({:call, from}, {:sign_block, block}, state) do
    sign_external_block(from, block, state)
  end

  def signature_collection({:call, from}, :get_state, state) do
    {:keep_state, state, [{:reply, from, state}]}
  end

  def signature_collection({:call, from}, :certification, trans) do

  end

  def signature_collection(call, message, state) do
    handle_unsupported(call, state, message, :signature_collection)
  end


  defp handle_unsupported({:call, from}, state, {message, _}, mode) do
    message = "Unsupported message: #{message}, in state #{mode}"
    {:keep_state, state, [{:reply, from, message}]}
  end

  defp handle_unsupported({:call, from}, state, _message, mode) do
    message = "Unsupported message in state #{mode}"
    {:keep_state, state, [{:reply, from, message}]}
  end

  defp handle_unsupported(:cast, _mode, _message, state) do
    {:keep_state, state, []}
  end


  #############################################################
  #                        Helpers                            #
  #                  Signing and Hashing                      #
  #############################################################

  @spec sign_external_block(pid(), T.signed_block_1(), state_1()) ::
                           {:keep_state, state_1(), any()}
  defp sign_external_block(from, signed_block, %{network: net, data: d}) do
    {%{pub_key: pub_key, block: block}, _} = signed_block
    case sign_if_valid(net, signed_block) do
      :error ->
        {:keep_state, %{network: net, data: d}, [{:reply, from, :error}]}
      signature ->
        block_storage = Map.put(net.blocks, digest_block(block), block)
        currently_seen = MapSet.put(net.signed_blocks_of_the_round, pub_key)
        new_net =
          net
          |> Map.put(:blocks, block_storage)
          |> Map.put(:signed_blocks_of_the_round, currently_seen)

        {:keep_state, %{data: d, network: new_net}, [{:reply, from, signature}]}
    end
  end

  @spec sign_if_valid(T.network(), T.signed_block_1()) :: T.signature() | :error
  defp sign_if_valid(
    %{signed_blocks_of_the_round: signed_blocks,
      round:                      round_validator,
      private_key:                priv,
      public_key:                 pub
    },
    {block = %{pub_key: validator_public_key, round: round_block}, signature}) do

    in_signed_set = MapSet.member?(signed_blocks, validator_public_key)

    valid_signature = valid_signature?(block, signature)

    same_round = round_validator == round_block

    # TODO For real code add the following checks
    # 1. number of blocks match what it should be
    # 2. check if all the signed messages are valid
    # 3. check if the keys all relate to actual validators
    if same_round && not in_signed_set && valid_signature && valid_block?(block) do
      %{signed: create_signature(block, priv), public_key: pub}
    else
      :error
    end
  end

  defp digest_block(b) do
    :crypto.hash(:blake2b, :erlang.term_to_binary(b))
  end

  #############################################################
  #                        Helpers                            #
  #          Creation: Certs, Blocks, Signatures              #
  #############################################################

  @spec create_signature(T.block_structure_1(), binary()) :: binary()
  def create_signature(%{block: b, round: r, pub_key: p}, priv_key) do
    message = :erlang.term_to_binary({digest_block(b), r, p})
    :crypto.sign(:rsa, :ripemd160, message, priv_key)
  end

  @spec create_block(state_1()) :: T.signed_block_1()
  def create_block(%{network: net, data: block}) do
    block     = %{block: block, round: net.round, pub_key: net.public_key}
    signature = create_signature(block, net.private_key)
    {block, signature}
  end


  @spec create_certificate(any(), T.block_1()) :: T.cert_1()
  def create_certificate(state, block) do
    %{hash: :crypto.hash(:blake2b, :erlang.term_to_binary(block)),

    }
  end


  #############################################################
  #                        Helpers                            #
  #                    Validity Checks                        #
  #############################################################

  # We don't do any computation in this test, but we should
  defp valid_transaction?(transaction) do
    _ = transaction
    true
  end

  @spec valid_signature?(T.block_structure_1(), binary()) :: binary()
  defp valid_signature?(%{block: b, round: r, pub_key: p}, signature) do
    message = :erlang.term_to_binary({digest_block(b), r, p})
    :crypto.verify(:rsa, :ripemd160, message, signature, p)
  end

  defp valid_certificate?(cert) do
    # we don't do any checking as we should. It is TRIVIAL to implement.
    # Just call:
    #
    # Stream.all? valid_cert
    # where valid_cert checks the certs are signing {digest, vlaidator, round}
    #
    # We don't do this for easier testing purposes, in reality DO THIS
    _ = cert
    true
  end

  defp valid_block?(block) do
    _ = block
    true
  end

  #############################################################
  #                        Helpers                            #
  #                         Misc                              #
  #############################################################

  # gen_statem does not give this out. so we have to copy it in
  def child_spec(opts) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [opts]},
      type: :worker,
      restart: :permanent,
      shutdown: 500
    }
  end

end

defmodule Misc.Narwhal.Communicator do
  @moduledoc """
  I communicate with other validators
  """
  require Misc.Narwhal.Validator
  use GenServer

  def start_link(arg) do
    GenServer.start_link(__MODULE__, arg, [])
  end

  def init(x), do: {:ok, x}

end
