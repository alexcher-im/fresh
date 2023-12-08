#pragma once


// library macros for implementing a stronger type system
// usage:
//  DEFINE_STRONG_TYPE(TypeName, BaseType, AvailableOperations...)
//  defines a type, named TypeName, which wraps type BaseType, limiting its publicly available operations.
//  AvailableOperations can be used to allow some limited functionality of BaseType for newly created TypeName
//   and are expressed as a list of DS_ and/or CDS_ macros
//
//  DS_ operator macros (like DS_SUM()) can have two optional arguments: return type and argument type:
//   return type overrides return type of operation (default is TypeName)
//   argument type overrides argument type of operation (default is TypeName)
//   e.g. DS_SUM() implements an operator+ between TypeName and TypeName, returning TypeName,
//    by applying operator+ on arguments internal types (BaseType)
//
//  other DS_ operator macros with a single optional argument allow to override argument type, keeping return type fixed
//   e.g. DS_EQ() implements operator== between TypeName and TypeName and returns bool, applying operator== as described above
//
//  DS_CONV_FUNC(RetType, func_name, body_expr) macro allows to implement custom conversion function,
//   named func_name, returning RetType, by applying a body body_expr
//
//  argument types of any operation functions must be created by current type system,
//   if you need to use a different type (like int), you will need to use a wrapped type
//  wrapped types must be pre-declared before usage with DEFINE_WRAPPED_TYPE(Type),
//   and its usages must be replaced with GET_WRAPPED_TYPE(Type)
//
//  DEFINE_STRONG_TYPE(), requires BaseType having a constexpr copy constructor
//  if you need to use a type without constexpr copy constructor, replace DEFINE_STRONG_TYPE with DEFINE_RT_STRONG_TYPE
//  DS_ functions are not constexpr, if you need a constexpr ones, use CDS_ analogues
//
//  example:
//   // defines a delta time type, that are allowed to be added together and can be multiplied by int
//   DEFINE_WRAPPED_TYPE(int)
//   DEFINE_STRONG_TYPE(TimeDeltaNs, int,
//                      DS_SUM()
//                      DS_MUL(TimeDeltaNs, GET_WRAPPED_TYPE(int)))
//   // defines time point type, that can be subtracted to produce TimeDeltaNs, can be added with TimeDeltaNs
//   //  to produce TimeNs, can output an integer amount of seconds with .get_seconds() function
//   DEFINE_STRONG_TYPE(TimeNs, int,
//                      DS_SUB(TimeDeltaNs)
//                      DS_SUM(TimeNs, TimeDeltaNs)
//                      DS_CONV_FUNC(GET_WRAPPED_TYPE(int), get_seconds, (_internal / 1'000'000))
//                      )


// impl macros
#define IMPL_GET_2_ARG(arg1, arg2, ...) arg2
#define IMPL_GET_3_ARG(arg1, arg2, arg3, ...) arg3
#define IMPL_SELECT1(Default, ...) IMPL_GET_2_ARG(Default, ##__VA_ARGS__, Default)
#define IMPL_SELECT2(Default, ...) IMPL_GET_3_ARG(Default, ##__VA_ARGS__, Default, Default)
#define IMPL_DS_GET_RET_TYPE(...) IMPL_SELECT1(SelfT, ##__VA_ARGS__)
#define IMPL_DS_GET_ARG_TYPE(...) IMPL_SELECT2(SelfT, ##__VA_ARGS__)

#define IMPL_DS_SUM(RetType, ArgType) RetType operator+(ArgType arg) const { return RetType::from_raw(_internal + arg._internal); }
#define IMPL_DS_SUB(RetType, ArgType) RetType operator-(ArgType arg) const { return RetType::from_raw(_internal - arg._internal); }
#define IMPL_DS_MUL(RetType, ArgType) RetType operator*(ArgType arg) const { return RetType::from_raw(_internal * arg._internal); }
#define IMPL_DS_DIV(RetType, ArgType) RetType operator/(ArgType arg) const { return RetType::from_raw(_internal / arg._internal); }

#define IMPL_DS_EQ(ArgType) bool operator==(ArgType arg) const { return _internal == arg._internal; }
#define IMPL_DS_GE(ArgType) bool operator>=(ArgType arg) const { return _internal >= arg._internal; }
#define IMPL_DS_LE(ArgType) bool operator<=(ArgType arg) const { return _internal <= arg._internal; }
#define IMPL_DS_GT(ArgType) bool operator>(ArgType arg) const { return _internal > arg._internal; }
#define IMPL_DS_LT(ArgType) bool operator<(ArgType arg) const { return _internal < arg._internal; }
#define IMPL_DS_CMP(ArgType) auto operator<=>(ArgType arg) const { return _internal <=> arg._internal; }

// main operations
#define DS_SUM(...) IMPL_DS_SUM(IMPL_DS_GET_RET_TYPE(__VA_ARGS__), IMPL_DS_GET_ARG_TYPE(__VA_ARGS__))
#define DS_SUB(...) IMPL_DS_SUB(IMPL_DS_GET_RET_TYPE(__VA_ARGS__), IMPL_DS_GET_ARG_TYPE(__VA_ARGS__))
#define DS_MUL(...) IMPL_DS_MUL(IMPL_DS_GET_RET_TYPE(__VA_ARGS__), IMPL_DS_GET_ARG_TYPE(__VA_ARGS__))
#define DS_DIV(...) IMPL_DS_DIV(IMPL_DS_GET_RET_TYPE(__VA_ARGS__), IMPL_DS_GET_ARG_TYPE(__VA_ARGS__))

#define DS_EQ(...) IMPL_DS_EQ(IMPL_DS_GET_RET_TYPE(__VA_ARGS__))
#define DS_GE(...) IMPL_DS_GE(IMPL_DS_GET_RET_TYPE(__VA_ARGS__))
#define DS_LE(...) IMPL_DS_LE(IMPL_DS_GET_RET_TYPE(__VA_ARGS__))
#define DS_GT(...) IMPL_DS_GT(IMPL_DS_GET_RET_TYPE(__VA_ARGS__))
#define DS_LT(...) IMPL_DS_LT(IMPL_DS_GET_RET_TYPE(__VA_ARGS__))
#define DS_CMP(...) IMPL_DS_CMP(IMPL_DS_GET_RET_TYPE(__VA_ARGS__))

// a custom conversion function, named func_name, returning RetType and evaluating expr
#define DS_CONV_FUNC(RetType, func_name, expr) RetType func_name() const { return RetType::from_raw(expr); }

// custom conversion operator, applied by casting strong type to RetType, evaluates expr
#define DS_CONV_OP(RetType, expr) operator RetType() const { return RetType::from_raw(expr); }

// custom cast constructor through another type, converts argument of type ArgType to CastPathType and to InternalT
#define DS_CAST_CTOR(SelfClassName, ArgType, CastPathType) SelfClassName(ArgType arg) : _internal((CastPathType) arg) { }

// default constructor for strong type. SelfClassName - current strong type
#define DS_DEF_CTOR(SelfClassName) SelfClassName() = default;

// custom implicit constructor for strong type SelfClassName, taking ArgType argument, evaluating converter
#define DS_ASSIGN_CTOR(SelfClassName, ArgType, converter) SelfClassName(ArgType arg) : _internal(converter) { }

// implicit cast operator to internal type
#define DS_ICONV_INT() operator InternalT() const { return _internal; } \
                                                                        \
// implicit constructor from internal type for strong type SelfClassName
#define DS_ICTOR(SelfClassName) SelfClassName(InternalT arg) : _internal(arg) { }

// implements std::hash for TypeName, doing std::hash<InternalT>()(_internal). must be called in global namespace
#define ODS_STD_HASH(TypeName) namespace std { template<> struct hash<TypeName> \
{ inline auto operator()(const TypeName& val) const {                           \
static_assert(std::is_same_v<::std::hash<TypeName>, hash<TypeName>>, "");       \
return std::hash<TypeName::InternalT>()(val._internal); } }; }

// constexpr main operations
#define CDS_SUM(...) constexpr DS_SUM(__VA_ARGS__)
#define CDS_SUB(...) constexpr DS_SUB(__VA_ARGS__)
#define CDS_MUL(...) constexpr DS_MUL(__VA_ARGS__)
#define CDS_DIV(...) constexpr DS_DIV(__VA_ARGS__)

#define CDS_EQ(...) constexpr DS_EQ(__VA_ARGS__)
#define CDS_GE(...) constexpr DS_GE(__VA_ARGS__)
#define CDS_LE(...) constexpr DS_LE(__VA_ARGS__)
#define CDS_GT(...) constexpr DS_GT(__VA_ARGS__)
#define CDS_LT(...) constexpr DS_LT(__VA_ARGS__)
#define CDS_CMP(...) constexpr DS_CMP(__VA_ARGS__)

#define CDS_CONV_FUNC(RetType, func_name, expr) constexpr DS_CONV_FUNC(RetType, func_name, expr)
#define CDS_CONV_OP(RetType, expr) constexpr DS_CONV_OP(RetType, expr)
#define CDS_ICONV_INT() constexpr DS_ICONV_INT()
#define CDS_ICTOR(SelfClassName) constexpr DS_ICTOR(SelfClassName)
#define CDS_DEF_CTOR(SelfClassName) constexpr DS_DEF_CTOR(SelfClassName)


class BaseStrongType { }; // just to check that some type is a strong type


#define DEFINE_RT_STRONG_TYPE(TypeName, BaseType, ...) \
struct TypeName : public BaseStrongType {              \
    BaseType _internal;                                \
    using SelfT = TypeName;                            \
    using InternalT = BaseType;                        \
                                                       \
    __VA_ARGS__                                        \
                                                       \
    static TypeName from_raw(BaseType raw) {           \
        return TypeName(raw);                          \
    }                                                  \
                                                       \
    protected:                                         \
    explicit TypeName(BaseType raw)                    \
        : _internal(raw) { }                           \
                                                       \
    TypeName& operator=(const BaseType& raw)           \
        { _internal = raw; return *this; }             \
}

#define DEFINE_STRONG_TYPE(TypeName, BaseType, ...)    \
struct TypeName : public BaseStrongType {              \
    BaseType _internal;                                \
    using SelfT = TypeName;                            \
    using InternalT = BaseType;                        \
                                                       \
    __VA_ARGS__                                        \
                                                       \
    constexpr static TypeName from_raw(BaseType raw) { \
        return TypeName(raw);                          \
    }                                                  \
                                                       \
    protected:                                         \
    constexpr explicit TypeName(BaseType raw)          \
        : _internal(raw) { }                           \
                                                       \
    constexpr TypeName& operator=(const BaseType& raw) \
        { _internal = raw; return *this; }             \
}


#define DEFINE_LOOSE_STRONG_TYPE(TypeName, BaseType, ...) \
struct TypeName : public BaseStrongType {                 \
    BaseType _internal;                                   \
    using SelfT = TypeName;                               \
    using InternalT = BaseType;                           \
                                                          \
    __VA_ARGS__                                           \
                                                          \
    constexpr static TypeName from_raw(BaseType raw) {    \
        return TypeName(raw);                             \
    }                                                     \
                                                          \
    constexpr TypeName(BaseType raw)                      \
        : _internal(raw) { }                              \
                                                          \
    constexpr TypeName& operator=(const BaseType& raw)    \
        { _internal = raw; return *this; }                \
}


#define IMPL_DEFINE_WRAPPED_TYPE(TypeName, BaseType)   \
struct TypeName {                                      \
    BaseType _internal;                                \
    using SelfT = TypeName;                            \
    using InternalT = BaseType;                        \
                                                       \
    constexpr static TypeName from_raw(BaseType raw) { \
        return TypeName(raw);                          \
    }                                                  \
    /* constructor must be public and implicit */      \
    constexpr TypeName(BaseType raw)                   \
        : _internal(raw) { }                           \
                                                       \
    constexpr operator BaseType() {                    \
        return _internal;                              \
    }                                                  \
}

#define DEFINE_WRAPPED_TYPE(BaseType) IMPL_DEFINE_WRAPPED_TYPE(_Wr##BaseType, BaseType)

#define GET_WRAPPED_TYPE(BaseType) _Wr##BaseType


// examples
//  DEFINE_WRAPPED_TYPE(int);
//  DEFINE_STRONG_TYPE(TimeDeltaNs, int,
//                     DS_SUM()
//                     DS_MUL(TimeDeltaNs, GET_WRAPPED_TYPE(int)));
//  DEFINE_STRONG_TYPE(TimeNs, int,
//                     DS_SUB(TimeDeltaNs)
//                     DS_SUM(TimeNs, TimeDeltaNs)
//                     DS_CONV_FUNC(GET_WRAPPED_TYPE(int), get_us, (_internal * 1'000'000))
//                     );
//  ODS_STD_HASH(TimeNs)
