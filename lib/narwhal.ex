defmodule Misc.Narwhal.Types do
  @moduledoc """

  I define out the types for the Narwhal protocol. I version out all
  my types for easier upgrading down the line
  """
  defmodule Block_1 do
    use TypedStruct

    typedstruct do
      field :transactions, list(),       default: []
      field :certificates, list(Cert_1), default: []
    end

    @spec new :: t()
    def new() do
      %Block_1{}
    end

    def valid?(block) do
      _ = block
      true
    end

    def digest(block) do
      :crypto.hash(:blake2b, :erlang.term_to_binary(block))
    end
  end

  defmodule Signature do

    use TypedStruct

    typedstruct do
      field :signature,  binary(), require: true
      field :pub_key  , binary(),  require: true
    end

    @spec verify(t(), binary()) :: boolean()
    def verify(sig, message) do
      :crypto.verify(:rsa, :ripemd160, message, sig.signature, sig.pub_key)
    end
  end

  defmodule BlockStructure_1 do
    use TypedStruct

    alias __MODULE__

    typedstruct do
      field :block,   Block_1.t(), require: true
      field :round,   integer(),   default: 0
      field :pub_key, binary(),    require: true
    end
  end

  defmodule Cert_1 do
    use TypedStruct

    typedstruct do
      field :digest,     binary(),  require: true
      # this should be a MapSet. To Avoid duplicates, for free
      field :signatures, list(),    default: []
      field :validator,  binary(),  require: true
      field :round,      integer(), default: 0
    end

    @doc """
    Checks if the certificate is valid
    """
    def valid?(cert) do
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
  end

  # with the block being signed
  @type signed_block_1 :: {BlockStructure_1.t(), binary()}

  defmodule SignedBlock_1 do
    @moduledoc """
    I represent a signed block, where the signature can either be

    1. A Signature.t(), which states that the given signature and
       public key signed the BlockStructure_1.t()

    2. A raw signature (binary()), where the public key of the signed
       block is stored within the BlockStructure_1.t() itself
    """
    use TypedStruct

    typedstruct do
      field :struct, BlockStructure_1.t(), require: true
      field :signature, binary() | Signature.t(), require: true
    end

    alias __MODULE__

    @spec valid?(t()) :: boolean()
    @doc """
    I check if the given signature with the block_structure is valid

    ### Parameters

    - block_structure: this is block structure given to use
    - signature: This can either be
    1. A cryptographic signature.
      + In this case, we are checking if the public key in the block
    signed the message
    2. A BlockStructure_1.t()
      + In this case we are checking if the tuple signed the block
    """
    def valid?(signed) do
      %SignedBlock_1{struct: %BlockStructure_1{block: b, round: r, pub_key: p}} =
        signed
      message = :erlang.term_to_binary({Block_1.digest(b), r, p})
      case signed.signature do
        sig=%Signature{} -> sig
        signature        -> %Signature{signature: signature, pub_key: p}
      end
      |> Signature.verify(message)
    end

    def of_type?(%SignedBlock_1{}) do
      true
    end

    def of_type?(_) do
      false
    end

  end

  defmodule Network do
    use TypedStruct

    alias __MODULE__

    typedstruct do
      # this is the value of 2f + 1 I guess
      field :total_signatures_required, integer(), require: true
      field :round, integer(), default: 0
      # Map the hash of a block to the block itself.
      field :blocks, map(), default: Map.new()
      # we keep track of the signed nodes at this round
      field :signed_blocks_of_the_round, MapSet.t(), default: MapSet.new()
      field :public_key, binary(), require: true
      field :private_key, binary(), require: true
    end

    @spec new(integer()) :: t()
    def new(signatures_needed) do
      {pub, priv} = :crypto.generate_key(:rsa, {1024,65537})
      %Network{public_key: pub,
               private_key: priv,
               total_signatures_required: signatures_needed }
    end
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
  alias Misc.Narwhal.Types.{SignedBlock_1, Block_1, Signature, BlockStructure_1, Cert_1, Network}
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
      [ {Misc.Narwhal.Primary, Network.new(3)},
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
    network: Network.t(),
    data: any()
  }

  @behaviour :gen_statem

  def callback_mode, do: :state_functions

  @type init() :: Network.t() | {:block, Network.t(), T.Block_1.t()}

  # TODO Use an AGENT to persist the last state before crash
  @spec init(init()) :: {:ok, :block_creation, state_1}
  def init({:block, config, block}),
    do: {:ok, :block_creation, %{network: config, data: block}}

  def init(net),
    do: {:ok,
         :block_creation,
         %{network: net, data: T.Block_1.new()}}

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

  def new_signature(primary, signature) do
    :gen_statem.call(primary, {:new_signature, signature})
  end

  @spec sign_block(pid(), SignedBlock_1.t()) :: any()
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
    if not valid_transaction?(transaction) do
      {:keep_state, state, []}
    else
      {_, new_state} =
        get_and_update_in(state, [:data, Access.key!(:transactions)], &{nil, [transaction | &1]})
      {:keep_state, new_state, []}
    end
  end

  def block_creation({:call, from}, {:new_certificate, cert}, state) do
      # the check is fake for now
      # this call can happen in the nested if to save computation... who cares
      net = state.network
      path_to_cert = [:data, Access.key!(:certificates)]
      {num_certs, new_state} =
        get_and_update_in(state, path_to_cert , &{length(&1) + 1, [cert | &1]})
      cond do
        not T.Cert_1.valid?(cert) ->
          {:keep_state, state, [{:reply, from, :error}]}
        num_certs < state.network.total_signatures_required ->
          {:keep_state, new_state, [{:reply, from, :ack}]}
        true ->
          %T.SignedBlock_1{struct: block_struct, signature: sig} = create_block(new_state)
          digest    = digest_block(block_struct.block)
          new_net   = Map.put(net, :blocks, Map.put(net.blocks, digest, block_struct))
          wip_cert  = %{signatures: [],
                        validator:  new_net.public_key,
                        digest:     digest,
                        round:      new_net.round}
          new_state = %{network: new_net, data: wip_cert}
          reply     = {:reply, from, %T.SignedBlock_1{struct: block_struct, signature: sig}}
          {:next_state, :signature_collection, new_state, [reply]}
      end
  end

  def block_creation({:call, from}, {:sign_block, block}, state) do

    if T.SignedBlock_1.of_type?(block) do
      sign_external_block(from, block, state)
    else
      handle_unsupported({:call,from}, {:sign_block, block}, state, :block_creation)
    end
  end

  def block_creation({:call, from}, :get_state, state),
    do: {:keep_state, state, [{:reply, from, state}]}

  def block_creation(call, message, state),
    do: handle_unsupported(call, state, message, :signature_collection)

  def signature_collection({:call, from}, {:new_signature, signature}, state) do
    %{network: net, data: data} = state
    certificate  = %{data | signatures: [signature | data.signatures]}
    num_sigs     = length(certificate.signatures)
    block_struct = Map.fetch!(net.blocks, data.digest)
    new_state    = %{network: net, data: certificate}
    cond do
      not T.SignedBlock_1.valid?(%T.SignedBlock_1{struct: block_struct, signature: signature}) ->
        {:keep_state, state, [{:reply, from, :error}]}
      num_sigs < net.total_signatures_required ->
        {:keep_state, new_state, [{:reply, from, :ack}]}
      true ->
        new_state =
          %{network:
            %{net | signed_blocks_of_the_round: MapSet.new(), round: net.round + 1},
            data: %{certificates: [certificate], transactions: []}
           }
        reply  = {:reply, from, certificate}
        {:next_state, :block_creation, new_state, [reply]}
    end
  end

  def signature_collection({:call, from}, {:sign_block, block}, state) do
    if T.SignedBlock_1.of_type?(block) do
      sign_external_block(from, block, state)
    else
      handle_unsupported({:call,from}, {:sign_block, block}, state, :signature_collection)
    end
  end

  def signature_collection({:call, from}, :get_state, state),
    do: {:keep_state, state, [{:reply, from, state}]}

  def signature_collection(call, message, state),
    do: handle_unsupported(call, state, message, :signature_collection)



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

  @spec sign_external_block(pid(), SignedBlock_1.t(), state_1()) ::
                           {:keep_state, state_1(), any()}
  defp sign_external_block(from, signed_block, %{network: net, data: d}) do
    %T.SignedBlock_1{struct: %T.BlockStructure_1{pub_key: pub_key, block: block}} = signed_block
    case sign_if_valid(net, signed_block) do
      :error ->
        {:keep_state, %{network: net, data: d}, [{:reply, from, :error}]}
      signature ->
        block_storage = Map.put(net.blocks, block, signed_block.struct)
        currently_seen = MapSet.put(net.signed_blocks_of_the_round, pub_key)
        new_net =
          net
          |> Map.put(:blocks, block_storage)
          |> Map.put(:signed_blocks_of_the_round, currently_seen)

        {:keep_state, %{data: d, network: new_net}, [{:reply, from, signature}]}
    end
  end

  @spec sign_if_valid(Network.t(), SignedBlock_1.t()) :: Signature.t() | :error
  defp sign_if_valid(
    %{signed_blocks_of_the_round: signed_blocks,
      round:                      round_validator,
      private_key:                priv,
      public_key:                 pub
    },
    signed_block) do

    %T.BlockStructure_1{pub_key: validator_public_key, round: round_block} = signed_block.struct
    in_signed_set = MapSet.member?(signed_blocks, validator_public_key)

    valid_signature = T.SignedBlock_1.valid?(signed_block)

    same_round = round_validator == round_block

    block = signed_block.struct

    # TODO For real code add the following checks
    # 1. number of blocks match what it should be
    # 2. check if all the signed messages are valid
    # 3. check if the keys all relate to actual validators
    if same_round && not in_signed_set && valid_signature && T.Block_1.valid?(block) do
      %T.Signature{signature: create_signature(block, priv), pub_key: pub}
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

  @spec create_signature(T.BlockStructure_1.t(), binary()) :: binary()
  def create_signature(%T.BlockStructure_1{block: b, round: r, pub_key: p}, priv_key) do
    message = :erlang.term_to_binary({digest_block(b), r, p})
    :crypto.sign(:rsa, :ripemd160, message, priv_key)
  end

  @spec create_block(state_1()) :: T.SignedBlock_1.t()
  def create_block(%{network: net, data: block}) do
    block     = %T.BlockStructure_1{block: block, round: net.round, pub_key: net.public_key}
    signature = create_signature(block, net.private_key)
    %T.SignedBlock_1{struct: block, signature: signature}
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
