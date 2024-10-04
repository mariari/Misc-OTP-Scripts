-module(raw).

-behaviour(wx_object).

-export([start/1, init/1, start_link/4, handle_event/2]).

-include_lib("wx/include/wx.hrl").

-record(state, {field = 4 :: integer()}).


%% Need to replace wx:null() with a meaningful empty parent
start(Object) ->
    wx_object:start_link(?MODULE, {wx:null(), self(), Object, []}, []).

start_link(Notebook, Parent, Object, Config) ->
    wx_object:start_link(?MODULE, {Notebook, Parent, Object, Config}, []).


init(Initial) ->
    wx:batch(fun() -> do_init(Initial) end).


do_init({Notebook, Parent, Object, Config}) ->
    Page = tree(Notebook, Object),
    {Page, #state{field = 1}}.

%% Tree version, lacks the ability to place objects, only text. Kind
%% of a sad limitation.

%% We could maybe make it work as we want
%% variable       | Item
%% v Tiles           Ordered Collection ...
%%   > { } array     an Array [4 items](1...)

%% Meaning we can maybe hack this to display an index/variable name
%% then the Object's printer method in the same frame

-spec tree(Parent, any()) -> wxPanel:wxPanel() when
      Parent::wxWindow:wxWindow().
tree(Notebook, Object) ->
    Panel    = wxPanel:new(Notebook, []),
    Columned = wxTreeCtrl:new(Panel, []),
    RootID   = wxTreeCtrl:addRoot(Columned, "Root"),

    raw(Object, Columned, RootID),

    wxTreeCtrl:expand(Columned, RootID),

    %% Setup sizers
    MainSizer = wxBoxSizer:new(?wxVERTICAL),
    Sizer = wxStaticBoxSizer:new(?wxVERTICAL, Panel, []),


    Options = [{flag, ?wxEXPAND}, {proportion, 1}],
    wxSizer:add(Sizer, Columned, Options),
    wxSizer:add(MainSizer, Sizer, Options),
    wxPanel:setSizer(Panel, MainSizer),

    wxTreeCtrl:connect(Columned, command_tree_item_right_click),

    Panel.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% raw item rendering
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-spec raw(Object, Tree, ID) -> ID when
      ID :: integer(),
      Object :: any(),
      Tree :: wxTreeCtrl:wxTreeCtrl().

raw(Object, Columned, RootID) when is_tuple(Object) ->
    raw(tuple_to_list(Object), Columned, RootID);

raw(Object, Columned, RootID) when is_list(Object) ->
    Id = wxTreeCtrl:appendItem(Columned, RootID, basicToString(Object), [{data, Object}]),

    Indexs  = lists:seq(1, length(Object)),
    raw_kv(lists:zip(Indexs, Object), Columned, Id),
    Id;


raw(Object, Columned, RootID) when is_map(Object) ->
    Id = wxTreeCtrl:appendItem(Columned, RootID, basicToString(Object), [{data, Object}]),

    raw_kv(maps:to_list(Object), Columned, Id),
    Id;

raw(Object, Columned, RootID) ->
    wxTreeCtrl:appendItem(Columned, RootID, basicToString(Object), [{data, Object}]).


raw_kv(PropertyList, Columned, RootID) ->
    wx:map(
      fun({Key, Value}) ->
              % We have this item, we should try raw on the value
              Message = lists:flatten(io_lib:format("~p: ~p",[Key, Value])),
              ItemID = raw(Value, Columned, RootID),
              wxTreeCtrl:setItemText(Columned, ItemID, Message)
      end,
      PropertyList).


basicToString(Object) ->
    lists:flatten(io_lib:format("~p",[Object])).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Behavior Handling
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%% We should abstract the menu logic into a general inspector menu
%% action

handle_event(
  #wx{event = #wxTree{type = command_tree_item_right_click, item = Item},
      obj = TreeCtrl},
  State = #state{}) ->
    %% TODO :: Make a menu spawn that gives some options

    RealItem = wxTreeCtrl:getItemData(TreeCtrl, Item),
    io:format("~p ~n", [RealItem]),
    %% Let us spawn our very own inspector on the piece of data
    inspector:start_link(RealItem, []),
    {noreply, State}.
